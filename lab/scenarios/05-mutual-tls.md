# 05 Mutual TLS

## Purpose

Demonstrate how server TLS validation and client-certificate acceptance are separate decisions. Compare a missing client certificate, a trusted client certificate and an untrusted client certificate against the same mTLS server.

This scenario exercises the Docker lab using curl and CertHub's API. The probe supports an optional operator-configured client PFX. Its report describes client-side TLS completion and server-certificate validation; it does not establish remote acceptance of the client credential.

## Setup

Follow [lab setup steps 1 and 2](../README.md) to generate a complete certificate set and export `CERTHUB_LAB_PFX_PASSWORD`. Run commands from the repository root.

- Endpoint: `https://localhost:8443/`, published on IPv4 loopback.
- Server certificate: `localhost.pfx`, issued by the generated lab CA with `DNS:localhost`.
- Client trust: curl explicitly trusts that CA through `--cacert`.
- Server trust: the lab server builds client certificate chains against the mounted lab CA using custom-root trust.
- Client certificate: `client.pfx`, issued by the same CA with client-authentication usage and its own private key.
- Revocation checking and automatic issuer downloads are disabled in this controlled lab.

The server accepts certificates under its configured client-chain policy. This exercise does not implement application user mapping, roles or authorization.

The current C# generator creates all required files. Earlier output sets may lack client credentials; generate a fresh complete set rather than mixing certificates from different runs. Generated material stays outside Git. Never mount the CA private key or client private credentials into the server.

## Enable mTLS

```bash
docker compose \
  -f lab/compose.yaml \
  -f lab/compose.mtls.yaml \
  config --quiet

docker compose \
  -f lab/compose.yaml \
  -f lab/compose.mtls.yaml \
  up --build -d

docker compose \
  -f lab/compose.yaml \
  -f lab/compose.mtls.yaml \
  logs tls-server
```

The override sets `LabTls__RequireClientCertificate` to `true` and `LabTls__ClientTrustRootPath` to `/certificates/client-trust-root.cert.pem`. It mounts the public CA certificate read-only at that path and inherits the valid server PFX mount from the base file.

The current generator makes the public CA certificate and server PFX readable by the container's non-root user. Missing or unreadable material must be corrected before proceeding. Compose configuration validation checks the merged configuration; startup is also required to verify that the files can be loaded.

## Expected results

| Client credentials | Expected service result | Observed curl result on macOS |
|---|---|---|
| None | Request is not served successfully | Empty reply, curl error `52` |
| Certificate issued by the trusted lab CA | Request succeeds | HTTP `200`, `Hello World!`, exit `0` |
| Certificate issued by a different CA | Request is not served successfully | Empty reply, curl error `52` |

All three checks continue to validate the server against the original lab CA. Only the supplied client credentials change.

## 1. No client certificate

```bash
curl --verbose --http1.1 --noproxy '*' \
  --cacert lab/certificates/generated/certhub-lab-root-ca.cert.pem \
  https://localhost:8443/
echo $?
```

Observed on 28 October 2026 with curl 8.7.1 on macOS:

```text
TLS handshake, Request CERT (13):
SSL certificate verify ok.
> GET / HTTP/1.1
* Request completely sent off
* Empty reply from server
curl: (52) Empty reply from server
52
```

These are selected evidence lines, not the complete trace. The client validated the server, but no successful HTTP response followed. In this run curl logged completion of its TLS exchange and sent a GET before detecting the closed connection. Do not interpret the client-side handshake message as proof that the server accepted the client.

## 2. Trusted client certificate

```bash
curl --verbose --http1.1 --noproxy '*' \
  --cacert lab/certificates/generated/certhub-lab-root-ca.cert.pem \
  --cert-type P12 \
  --cert lab/certificates/generated/client.pfx \
  --pass "$CERTHUB_LAB_PFX_PASSWORD" \
  https://localhost:8443/
echo $?
```

The generator uses the same confirmed PFX password for the server and client bundles. Supply it explicitly: the curl backend used for this run did not prompt when it was omitted and instead reported error `58`, a local PFX-loading failure.

Observed evidence:

```text
TLS handshake, Request CERT (13):
SSL certificate verify ok.
> GET / HTTP/1.1
< HTTP/1.1 200 OK
Hello World!
```

The command exited with `0`. The trace also showed the client sending a certificate and CertificateVerify. Together with the HTTP response under the mandatory-client-certificate configuration, this demonstrates successful mutual authentication for this controlled case.

Optional independent verification of the generated client's certificate:

```bash
openssl verify \
  -CAfile lab/certificates/generated/certhub-lab-root-ca.cert.pem \
  -purpose sslclient \
  lab/certificates/generated/client.cert.pem
```

Expected: `OK`. This checks certificate validation offline; it does not replace the live connection check.

## 3. Client certificate from a different CA

Create a second independent certificate set in a temporary directory. The following temporary-directory command uses Bash/zsh; Windows users can create an equivalent temporary parent directory and pass its output path to the generator.

```bash
untrusted_client_trial_dir="$(mktemp -d)"
dotnet run --file lab/tools/GenerateCertificates.cs -- \
  "$untrusted_client_trial_dir/generated"
```

For this exercise, use the same PFX password as the first set so the existing environment variable can load either client bundle. The standalone PEM-key password is independent.

Keep the server running with the original certificate and trust root. Use only the second set's client PFX:

```bash
curl --verbose --http1.1 --noproxy '*' \
  --cacert lab/certificates/generated/certhub-lab-root-ca.cert.pem \
  --cert-type P12 \
  --cert "$untrusted_client_trial_dir/generated/client.pfx" \
  --pass "$CERTHUB_LAB_PFX_PASSWORD" \
  https://localhost:8443/
echo $?
```

Observed evidence:

```text
SSL certificate verify ok.
> GET / HTTP/1.1
* Request completely sent off
* Empty reply from server
curl: (52) Empty reply from server
```

The client sent its certificate and CertificateVerify, but received no successful response. The original server trust configuration accepts the first CA, not the independently generated second CA. Matching CA subject names do not make their keys or trust anchors identical.

An empty reply alone does not identify a certificate-chain error. Here, the controlled change of client issuer and the server's configured validation policy establish the rejection scenario. TLS alerts and curl error codes can differ across platforms and TLS backends; record actual evidence rather than requiring error `52` everywhere.

## 4. CertHub API walkthrough and TLS 1.2 comparison

The following walkthrough was exercised on macOS on 10 November 2026 with a newly generated certificate set. The API ran on the host, and the Docker lab required client authentication. The probe negotiated TLS 1.2; curl 8.7.1 negotiated TLS 1.3 by default. The direct comparison below pins curl to TLS 1.2 so it uses the same protocol version as the observed probe connection. HTTP/1.1 and TLS version are independent settings.

### Configure the API with a trusted client credential

Keep the mTLS lab running. In the terminal that will launch the API, from the repository root:

```bash
dotnet user-secrets set "TlsProbe:TrustMode" "CustomRoots" --project src/CertHub.Api
dotnet user-secrets set "TlsProbe:TrustConfigurationId" "certhub-lab" --project src/CertHub.Api
dotnet user-secrets set "TlsProbe:RootCertificatePaths:0" \
  "$(pwd)/lab/certificates/generated/certhub-lab-root-ca.cert.pem" \
  --project src/CertHub.Api
dotnet user-secrets set "TlsProbe:ClientCertificatePath" \
  "$(pwd)/lab/certificates/generated/client.pfx" \
  --project src/CertHub.Api

export TlsProbe__ClientCertificatePassword="${CERTHUB_LAB_PFX_PASSWORD:?Set the lab PFX password first}"

dotnet run --project src/CertHub.Api/CertHub.Api.csproj --launch-profile https
```

The export command reuses the generator's PFX password without placing its literal value in command history. The environment value is plain text and must be set in the API's launching terminal. Existing configuration overrides can take precedence; remove unrelated root entries or credential overrides from earlier experiments. The [API guide](../../docs/api/tls-diagnostics.md) provides configuration and PowerShell alternatives.

In a second terminal, call the API:

```bash
curl --silent --show-error --http1.1 --noproxy '*' \
  -X POST https://localhost:7297/diagnostics/tls \
  -H 'Content-Type: application/json' \
  -d '{"hostname":"localhost","port":8443}' \
  -w '\nHTTP status: %{http_code}\n'
```

curl connects to the API on port `7297`; the API independently probes the lab on port `8443`. The API uses its separate ASP.NET Core development certificate. The client PFX is loaded by the probe from configuration, so it is not passed in the HTTP request.

Observed: HTTP `200`, all four diagnostic stages `Passed`, `CustomRoots` trust with configuration ID `certhub-lab`, TLS `Tls12`, and cipher suite `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.

### Repeat without a configured client credential

Stop the API with Ctrl+C. In its launching terminal, from the repository root:

```bash
dotnet user-secrets remove "TlsProbe:ClientCertificatePath" --project src/CertHub.Api
unset TlsProbe__ClientCertificatePassword

dotnet run --project src/CertHub.Api/CertHub.Api.csproj --launch-profile https
```

Remove any other client path or password overrides if you previously configured them. Leave server trust and the Docker mTLS configuration unchanged. Repeat the API request from the second terminal.

Observed again: HTTP `200`, all four stages `Passed`, and `Tls12`. The server-certificate and root fingerprints matched the credential-enabled run. This demonstrates the reporting limitation: these outcomes alone do not distinguish whether the server accepted the client. The API response contains no server-side client-authentication observation.

### Compare direct TLS 1.2 application access

From the repository root, call the lab directly without a client certificate:

```bash
curl --verbose --http1.1 --tlsv1.2 --tls-max 1.2 --noproxy '*' \
  --cacert lab/certificates/generated/certhub-lab-root-ca.cert.pem \
  https://localhost:8443/
echo $?
```

Observed: server certificate verification succeeded and the TLS 1.2 exchange completed, but the HTTP GET received an empty reply. curl reported error `52` and exited with `52`.

Now supply the trusted client PFX in the terminal containing the lab password:

```bash
curl --verbose --http1.1 --tlsv1.2 --tls-max 1.2 --noproxy '*' \
  --cacert lab/certificates/generated/certhub-lab-root-ca.cert.pem \
  --cert-type P12 \
  --cert lab/certificates/generated/client.pfx \
  --pass "$CERTHUB_LAB_PFX_PASSWORD" \
  https://localhost:8443/
echo $?
```

Observed: the client sent CertificateVerify, the server returned HTTP `200` with `Hello World!`, and curl exited with `0`.

| Check on 10 November 2026 | Client credential | Negotiated TLS | Observed result |
|---|---|---|---|
| CertHub API diagnostic | Trusted client PFX configured | TLS 1.2 | HTTP `200`; all report stages `Passed` |
| CertHub API diagnostic | None configured | TLS 1.2 | HTTP `200`; all report stages `Passed` |
| Direct curl request | None supplied | TLS 1.2, explicitly pinned | Empty reply; exit `52` |
| Direct curl request | Trusted client PFX supplied | TLS 1.2, explicitly pinned | HTTP `200`, `Hello World!`; exit `0` |

The API's HTTP status describes delivery of a diagnostic report. Direct curl's HTTP status describes the lab's response to an application request. These are different observations. The controlled direct comparison supports credential-dependent application access; an empty reply on its own does not identify a particular certificate-validation cause.

### Restore client credentials and verify

Stop the API, restore its client path and password, and restart from the same terminal:

```bash
dotnet user-secrets set "TlsProbe:ClientCertificatePath" \
  "$(pwd)/lab/certificates/generated/client.pfx" \
  --project src/CertHub.Api
export TlsProbe__ClientCertificatePassword="${CERTHUB_LAB_PFX_PASSWORD:?Set the lab PFX password first}"
dotnet run --project src/CertHub.Api/CertHub.Api.csproj --launch-profile https
```

Repeat the API request. The final recorded response at `2026-11-10T11:29:40.417431+00:00` returned HTTP `200` with all four stages `Passed`. Selected evidence from that response:

```json
{
  "dnsResolution": "Passed",
  "tcpConnection": "Passed",
  "tlsAuthentication": "Passed",
  "certificateValidation": "Passed",
  "connection": {
    "remoteIpAddress": "127.0.0.1",
    "tlsProtocol": "Tls12",
    "cipherSuite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
  },
  "certificate": {
    "sha256Fingerprint": "C4FC2F0146E531CE98A6B6B4C4164D46CE5EFEF9A918438ADB49B52A789C8905"
  },
  "trustContext": {
    "mode": "CustomRoots",
    "configurationId": "certhub-lab",
    "rootSha256Fingerprints": [
      "59F582D34ED85989AFA861D336C80E7292C2E5F0587E4822546E6AB31749D0FC"
    ]
  }
}
```

This is an excerpt, not the complete response contract. Newly generated certificates have different fingerprints and dates. The full response also retained the initial IPv6 connection-refused finding before successful IPv4 fallback.

The walkthrough verifies API configuration, credential loading and a connection to the real Docker lab. It does not independently reveal which client certificate the Docker server observed during each probe attempt. Separate loopback integration tests use server-side fingerprints to verify that the configured credential was presented and authenticated.

## Interpretation

The checks demonstrated acceptance with a trusted client credential and rejection with missing or untrusted credentials on the tested macOS/Docker setup. Server trust remained unchanged throughout.

curl may first fail to connect to IPv6 `::1` before connecting to `127.0.0.1`, because the published port is IPv4-only. That TCP fallback is unrelated to certificate validation.

These records are manual macOS/Docker observations. The product also has separate automated loopback mTLS tests for trusted, missing and presented untrusted client credentials. Manual results do not establish cross-platform runtime validation of the generator.

## Cleanup and restore server TLS

Stop the API with Ctrl+C. If client credentials were configured only for this walkthrough, remove the path and password settings:

```bash
dotnet user-secrets remove "TlsProbe:ClientCertificatePath" --project src/CertHub.Api
unset TlsProbe__ClientCertificatePassword
```

Also remove `TlsProbe:ClientCertificatePassword` from User Secrets if you set it there. Restore any pre-existing values instead of removing them if you use those settings for other work. The [lab setup guide](../README.md#cleanup-and-regeneration) covers removal of temporary custom-root trust settings. Restart the API after changing its configuration.

Stop the mTLS lab:


```bash
docker compose \
  -f lab/compose.yaml \
  -f lab/compose.mtls.yaml \
  down
```

Keep `CERTHUB_LAB_PFX_PASSWORD` set until Compose cleanup completes; it is separate from the API password setting. After all lab commands are finished, unset it if it was supplied only for this exercise. Remove the temporary untrusted-client output when it is no longer needed, keeping it outside the repository.

To return to ordinary server TLS:

```bash
docker compose -f lab/compose.yaml up -d
```

Repeat the valid-server curl command without client credentials. It should return HTTP `200` while the server certificate remains valid. Stop the base service with `docker compose -f lab/compose.yaml down` when finished.

If you used an additional temporary Compose override during testing, include that override with the same project configuration for startup and cleanup. Relative bind sources are resolved from the first Compose file's directory; use absolute sources for certificate sets outside the standard lab directory.
