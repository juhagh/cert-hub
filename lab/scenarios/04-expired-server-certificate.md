# 04 Expired Server Certificate

## Purpose

Demonstrate rejection of an expired server certificate while preserving certificate evidence and identifying expiry as a diagnostic finding.

## Setup

- Server: `CertHub.Lab.Server` runs in Docker, using the expired-certificate Compose override.
- Clients: curl on the host machine and the CertHub API running on the host machine.
- Target endpoint: `https://localhost:8443/`.
- Certificate authority: the existing locally generated CertHub Lab Root CA.
- Server certificate: a separate CA-issued certificate with `DNS:localhost` in its Subject Alternative Name, valid from 10 October 2026 until 11 October 2026 UTC.
- Trust: curl receives the root CA's public certificate through `--cacert`; CertHub uses the same CA through custom-root trust. The lab CA is not added to the machine's system trust store. The separate ASP.NET Core development certificate is trusted for HTTPS requests to the API.
- Authentication: server TLS only; no client certificate is requested.

The lab CA is valid from 7 October 2026 at 04:20:38 UTC until 7 October 2027 at 04:20:38 UTC. Run this scenario while the CA remains valid and after the server certificate has expired. If regenerating the CA, choose a new expired server-certificate validity window inside that CA's lifetime.

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

### 1. Generate the expired server certificate

Prerequisites: OpenSSL 3.6, the existing lab CA certificate and private key, the localhost CSR and matching private key, and `lab/certificates/localhost.ext.cnf`.

Inspect the CA's validity before signing:

```bash
openssl x509 \
  -in lab/certificates/generated/certhub-lab-root-ca.cert.pem \
  -noout -dates
```

Issue a separate certificate using explicit historical UTC dates:

```bash
openssl x509 -req \
  -in lab/certificates/generated/localhost.csr.pem \
  -CA lab/certificates/generated/certhub-lab-root-ca.cert.pem \
  -CAkey lab/certificates/generated/certhub-lab-root-ca.key.pem \
  -CAcreateserial \
  -sha256 \
  -not_before 20261010000000Z \
  -not_after 20261011000000Z \
  -extfile lab/certificates/localhost.ext.cnf \
  -extensions server_certificate \
  -out lab/certificates/generated/localhost-expired.cert.pem
```

This controlled lab scenario reuses the localhost key and CSR. It does not replace the existing valid certificate.

Inspect the issued certificate:

```bash
openssl x509 \
  -in lab/certificates/generated/localhost-expired.cert.pem \
  -noout -subject -issuer -dates -ext subjectAltName
```

Verify it against the trusted lab CA and intended hostname:

```bash
openssl verify \
  -CAfile lab/certificates/generated/certhub-lab-root-ca.cert.pem \
  -purpose sslserver \
  -verify_hostname localhost \
  lab/certificates/generated/localhost-expired.cert.pem
```

Verification failure is expected: the server certificate has expired.

### 2. Package the certificate and key

```bash
openssl pkcs12 -export \
  -inkey lab/certificates/generated/localhost.key.pem \
  -in lab/certificates/generated/localhost-expired.cert.pem \
  -out lab/certificates/generated/localhost-expired.pfx
```

OpenSSL prompts for the private-key passphrase and a PFX export password. Supply that export password through `CERTHUB_LAB_PFX_PASSWORD` in the terminal used to run Compose. Keep passwords out of committed files and recorded evidence.

Generated certificates, keys and PFX files remain under the ignored `lab/certificates/generated/` directory.

### 3. Select the expired-certificate override

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

### 4. Verify rejection with curl

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

### 5. Run the diagnostic through CertHub

In the API's local Development configuration, retain the allowed target `localhost:8443` and configure the probe with custom-root trust:

```json
{
  "TlsProbe": {
    "Timeout": "00:00:10",
    "TrustMode": "CustomRoots",
    "TrustConfigurationId": "certhub-lab",
    "RootCertificatePaths": [
      "/absolute/path/to/CertHub/lab/certificates/generated/certhub-lab-root-ca.cert.pem"
    ]
  }
}
```

Merge this section into the existing configuration rather than replacing the whole file. Replace the example path with the actual absolute path on your machine. Keep machine-specific paths out of shared configuration commits.

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

Keep the API's custom-root trust settings unchanged and repeat the diagnostic request from step 5.

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

Compose requires `CERTHUB_LAB_PFX_PASSWORD` to be set when processing either configuration, including during cleanup. Stop the API separately if it was started for this scenario, and restore temporary local probe settings when finished. Keep machine-specific certificate paths and passwords out of shared configuration commits.
