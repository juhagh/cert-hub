# 04 Expired Server Certificate

## Purpose

Demonstrate rejection of an expired server certificate while preserving certificate evidence and identifying expiry as a diagnostic finding.

## Setup

- Server: `CertHub.Lab.Server` runs in Docker, using the expired-certificate Compose override.
- Clients: curl on the host machine and the CertHub API running on the host machine.
- Target endpoint: `https://localhost:8443/`.
- Certificate authority: the existing locally generated CertHub Lab Root CA.
- Server certificate: a separate CA-issued certificate with `DNS:localhost` in its Subject Alternative Name, generated with a validity window from two days ago until one day ago.
- Trust: curl receives the root CA's public certificate through `--cacert`; CertHub uses the same CA through custom-root trust. The lab CA is not added to the machine's system trust store. The separate ASP.NET Core development certificate is trusted for HTTPS requests to the API.
- Authentication: server TLS only; no client certificate is requested.

The generator backdates the CA by seven days so the expired server certificate's validity window fits inside its lifetime. Run the scenario while the CA remains valid. The fixed October 2026 dates in the evidence section describe the original run; newly generated certificates use dates relative to generation time.

The existing valid server certificate and `localhost.pfx` are preserved. This scenario uses `localhost-expired.cert.pem` and `localhost-expired.pfx` instead.

## Expected result

- The issuing lab CA is trusted and the server hostname matches `localhost`.
- TCP connection succeeds.
- curl rejects the expired certificate, exits with code `60` and sends no HTTP request to the target.
- CertHub returns HTTP `200` with a diagnostic report: DNS and TCP pass; TLS authentication and certificate validation fail.
- Findings include `CERT_EXPIRED`, `CERT_CHAIN_INVALID` and `TLS_AUTHENTICATION_FAILED`, with no `CERT_HOSTNAME_MISMATCH` or `CERT_NOT_YET_VALID` finding.
- The report preserves certificate metadata, including an expiry date before `trustContext.evaluationTime`.

HTTP `200` from CertHub means that it returned a diagnostic report, not that the target passed validation. CertHub sends no HTTP request to the target.

## Run

Run commands from the repository root unless stated otherwise.

### 1. Prepare the generated certificate set

Follow the [lab setup guide](../README.md) for prerequisites, password prompts and output handling. From a fresh clone, generate the certificate set from the repository root:

```bash
bash lab/scripts/generate-certificates.sh
```

The script creates both `localhost.pfx` and `localhost-expired.pfx`, sharing the server key and hostname but using different validity windows. Use the same PFX export password for both when prompted, then supply it through `CERTHUB_LAB_PFX_PASSWORD` as described in the setup guide.

If a suitable generated set already exists, reuse it. Do not rerun the generator or overwrite the valid certificate merely to select the expired scenario. Keep generated material under the ignored directory and passwords out of recorded evidence.

Inspect the expired certificate if needed:

```bash
openssl x509 \
  -in lab/certificates/generated/localhost-expired.cert.pem \
  -noout -subject -issuer -dates -ext subjectAltName
```

The generator already checks valid-certificate acceptance and the expected expiry failure. To repeat the latter independently:

```bash
openssl verify \
  -CAfile lab/certificates/generated/certhub-lab-root-ca.cert.pem \
  -purpose sslserver \
  -verify_hostname localhost \
  lab/certificates/generated/localhost-expired.cert.pem
```

Expect a nonzero exit with `error 10 at 0 depth lookup: certificate has expired`.

### 2. Select the expired-certificate override

The [`lab/compose.expired.yaml`](../compose.expired.yaml) override replaces the `tls-server` volume at `/certificates/localhost.pfx` with the source `./certificates/generated/localhost-expired.pfx`, using a read-only bind mount and `create_host_path: false`.

The container certificate path stays unchanged. The override selects the expired PFX in place of the valid PFX.

Validate the merged configuration without displaying the password:

```bash
docker compose \
  -f lab/compose.yaml \
  -f lab/compose.expired.yaml \
  config --quiet
```

Start the lab with the override:

```bash
docker compose \
  -f lab/compose.yaml \
  -f lab/compose.expired.yaml \
  up --build -d
```

Inspect startup logs:

```bash
docker compose \
  -f lab/compose.yaml \
  -f lab/compose.expired.yaml \
  logs tls-server
```

### 3. Verify rejection with curl

```bash
curl \
  --verbose \
  --noproxy '*' \
  --cacert lab/certificates/generated/certhub-lab-root-ca.cert.pem \
  https://localhost:8443/

echo $?
```

Record the certificate-expiry error and exit code. Do not use `--insecure`, which disables the validation this scenario is demonstrating.

The base Compose file publishes IPv4 loopback only. An initial refusal on `::1`, followed by connection to `127.0.0.1`, is separate from the certificate-expiry failure.

### 4. Run the diagnostic through CertHub

Retain the shared Development allowlist entry for `localhost:8443`. Configure the machine-specific trust settings through .NET User Secrets rather than editing the tracked `appsettings.Development.json` file.

The API project already includes a `UserSecretsId`; initialization is not required. Run from the repository root, replacing the example path with the actual absolute path on your machine:

```bash
dotnet user-secrets set "TlsProbe:TrustMode" "CustomRoots" --project src/CertHub.Api
dotnet user-secrets set "TlsProbe:TrustConfigurationId" "certhub-lab" --project src/CertHub.Api
dotnet user-secrets set "TlsProbe:RootCertificatePaths:0" \
  "/absolute/path/to/CertHub/lab/certificates/generated/certhub-lab-root-ca.cert.pem" \
  --project src/CertHub.Api
```

The final `:0` sets the first root-certificate path. The probe uses its default ten-second timeout. User Secrets load automatically when the API runs in Development, and their values remain outside the repository. They are not encrypted. See the [API configuration guide](../../docs/api/tls-diagnostics.md#local-lab-settings-with-user-secrets) for configuration precedence and further details.

Start or restart the API so it uses the custom-root settings:

```bash
dotnet run --project src/CertHub.Api/CertHub.Api.csproj --launch-profile https
```

In another terminal, submit the diagnostic:

```bash
curl --silent --show-error --noproxy '*' \
  -X POST https://localhost:7297/diagnostics/tls \
  -H 'Content-Type: application/json' \
  -d '{"hostname":"localhost","port":8443}' \
  -w '\nHTTP status: %{http_code}\n'
```

Requests to the API use the trusted ASP.NET Core development certificate. If curl cannot validate that certificate, run `dotnet dev-certs https --trust`, approve the macOS prompt and restart the API. The probe's custom-root settings apply to the target connection, not the connection from curl to the API.

## Evidence

The following records the original checks on 25 October 2026. Preserve it as observed evidence; certificates produced by the generator will have different dates and fingerprints.

### Completed: certificate inspection

```text
subject=CN=localhost
issuer=CN=CertHub Lab Root CA
notBefore=Oct 10 00:00:00 2026 GMT
notAfter=Oct 11 00:00:00 2026 GMT
X509v3 Subject Alternative Name:
    DNS:localhost
```

### Completed: offline verification

```text
CN=localhost
error 10 at 0 depth lookup: certificate has expired
error lab/certificates/generated/localhost-expired.cert.pem: verification failed
```

Depth `0` identifies the server certificate.

### Completed: live verification - 25 October 2026

The expired certificate was rejected over a successful IPv4 TCP connection. The following curl excerpt records the target validation failure; no HTTP request was sent to the lab server:

```text
* Connected to localhost (127.0.0.1) port 8443
* SSL certificate problem: certificate has expired
curl: (60) SSL certificate problem: certificate has expired
```

The immediately following `echo $?` returned `60`.

The CertHub API returned the following report at 06:09:16 UTC. HTTP `200` confirms report delivery; the target's TLS authentication and certificate validation failed:

```json
{
    "hostname": "localhost",
    "port": 8443,
    "attemptedAt": "2026-10-25T06:09:16.838215+00:00",
    "dnsResolution": "Passed",
    "tcpConnection": "Passed",
    "tlsAuthentication": "Failed",
    "certificateValidation": "Failed",
    "connection": {
        "remoteIpAddress": "127.0.0.1",
        "tcpConnectDuration": "00:00:00.0045670",
        "tlsProtocol": null,
        "cipherSuite": null,
        "applicationProtocol": null
    },
    "certificate": {
        "subject": "CN=localhost",
        "issuer": "CN=CertHub Lab Root CA",
        "notBefore": "2026-10-10T00:00:00+00:00",
        "notAfter": "2026-10-11T00:00:00+00:00",
        "sha256Fingerprint": "44CF779C9CF402E414F350902FA4A99363DF2286CF1CDEC6BB0DA827676C05EE"
    },
    "trustContext": {
        "mode": "CustomRoots",
        "configurationId": "certhub-lab",
        "rootSha256Fingerprints": [
            "5F638845C47C2BD0E050D4D2DD5CE290A2CC8707F22A8D0D431C6BBB997BB750"
        ],
        "evaluationTime": "2026-10-25T06:09:16.838215+00:00"
    },
    "findings": [
        {
            "code": "TCP_CONNECTION_FAILED",
            "message": "::1 - ConnectionRefused: Connection refused"
        },
        {
            "code": "CERT_EXPIRED",
            "message": "The server certificate has expired."
        },
        {
            "code": "CERT_CHAIN_INVALID",
            "message": "Chain validation failed under the configured policy. [NotTimeValid: An expired certificate was detected.]"
        },
        {
            "code": "TLS_AUTHENTICATION_FAILED",
            "message": "The remote certificate was rejected by the provided RemoteCertificateValidationCallback."
        }
    ]
}
```
`HTTP status: 200`

The report records `CustomRoots` trust with configuration ID `certhub-lab`, preserves the expired certificate's metadata, and includes `CERT_EXPIRED`, `CERT_CHAIN_INVALID` with `NotTimeValid`, and `TLS_AUTHENTICATION_FAILED`. It contains no hostname-mismatch or not-yet-valid finding.

The `::1` connection refusal records the earlier IPv6 attempt. The overall TCP outcome passed because the subsequent IPv4 connection succeeded.

## Resolution

Issue and deploy a replacement server certificate whose validity period includes the current time, then repeat the check. Verify its hostname and trust chain as well as its dates.

For this lab, restore the existing valid `localhost.pfx`, provided that certificate is still valid. Stop the overridden service:

```bash
docker compose \
  -f lab/compose.yaml \
  -f lab/compose.expired.yaml \
  down
```

Ensure `CERTHUB_LAB_PFX_PASSWORD` now matches the valid PFX's export password, then start the base configuration:

```bash
docker compose -f lab/compose.yaml up -d
```

Keep the API's custom-root trust settings unchanged and repeat the diagnostic request from step 4.

### Completed: recovery verification - 25 October 2026

At 06:28:50 UTC, restoring the valid PFX resolved the failure under the same custom-root trust configuration and root fingerprint. All four stages passed, certificate and negotiated TLS details were captured, and no certificate or TLS failure findings remained.

```json
{
  "hostname": "localhost",
  "port": 8443,
  "attemptedAt": "2026-10-25T06:28:50.354207+00:00",
  "dnsResolution": "Passed",
  "tcpConnection": "Passed",
  "tlsAuthentication": "Passed",
  "certificateValidation": "Passed",
  "connection": {
    "remoteIpAddress": "127.0.0.1",
    "tcpConnectDuration": "00:00:00.0047342",
    "tlsProtocol": "Tls12",
    "cipherSuite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "applicationProtocol": null
  },
  "certificate": {
    "subject": "CN=localhost",
    "issuer": "CN=CertHub Lab Root CA",
    "notBefore": "2026-10-07T04:38:12+00:00",
    "notAfter": "2027-01-05T04:38:12+00:00",
    "sha256Fingerprint": "80E68459EEE4DC63E177B92F7F45FFA518B3FC9A6F99493FE3EACC29AA65C421"
  },
  "trustContext": {
    "mode": "CustomRoots",
    "configurationId": "certhub-lab",
    "rootSha256Fingerprints": [
      "5F638845C47C2BD0E050D4D2DD5CE290A2CC8707F22A8D0D431C6BBB997BB750"
    ],
    "evaluationTime": "2026-10-25T06:28:50.354207+00:00"
  },
  "findings": [
    {
      "code": "TCP_CONNECTION_FAILED",
      "message": "::1 - ConnectionRefused: Connection refused"
    }
  ]
}
```

HTTP status: `200`.

The valid server certificate expires on 5 January 2027. Its SHA-256 fingerprint differs from the expired certificate's fingerprint, confirming the certificate replacement. The remaining `TCP_CONNECTION_FAILED` finding concerns only the initial IPv6 attempt; IPv4 completed successfully. TLS 1.2 and the cipher suite shown above are observations from this run, not fixed requirements of the scenario.

## Cleanup

After the recovery check, the base configuration is running. Stop it with:

```bash
docker compose -f lab/compose.yaml down
```

If stopping before recovery, while the expired override is still selected, use both files instead:

```bash
docker compose \
  -f lab/compose.yaml \
  -f lab/compose.expired.yaml \
  down
```

Compose requires `CERTHUB_LAB_PFX_PASSWORD` to be set when processing either configuration, including during cleanup. User Secrets configure the API, not the Compose environment or the lab server's PFX password.

Keep the API's custom-root settings unchanged until recovery verification is complete. Afterward, if these values were added only for the scenario, remove them:

```bash
dotnet user-secrets remove "TlsProbe:TrustMode" --project src/CertHub.Api
dotnet user-secrets remove "TlsProbe:TrustConfigurationId" --project src/CertHub.Api
dotnet user-secrets remove "TlsProbe:RootCertificatePaths:0" --project src/CertHub.Api
```

Remove any additional root-array entries or other temporary probe overrides you added. Stop the API separately if it was started for this scenario; restart it before another check if you want the configuration changes applied. With no other trust overrides, the probe returns to system trust. Generated certificates remain available for later lab runs; cleanup does not delete them.
