# 05 Mutual TLS

## Purpose

Demonstrate how server TLS validation and client-certificate acceptance are separate decisions. Compare a missing client certificate, a trusted client certificate and an untrusted client certificate against the same mTLS server.

This scenario exercises the Docker lab using curl. CertHub's probe currently performs server TLS diagnostics only and does not supply client credentials.

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

## Interpretation

The checks demonstrated acceptance with a trusted client credential and rejection with missing or untrusted credentials on the tested macOS/Docker setup. Server trust remained unchanged throughout.

curl may first fail to connect to IPv6 `::1` before connecting to `127.0.0.1`, because the published port is IPv4-only. That TCP fallback is unrelated to certificate validation.

These are manual lab observations. They do not add automated mTLS coverage to the product's test suite or establish cross-platform runtime validation of the generator.

## Cleanup and restore server TLS

```bash
docker compose \
  -f lab/compose.yaml \
  -f lab/compose.mtls.yaml \
  down
```

Keep the PFX password environment variable set until Compose cleanup completes. Remove the temporary untrusted-client output when it is no longer needed, keeping it outside the repository.

To return to ordinary server TLS:

```bash
docker compose -f lab/compose.yaml up -d
```

Repeat the valid-server curl command without client credentials. It should return HTTP `200` while the server certificate remains valid. Stop the base service with `docker compose -f lab/compose.yaml down` when finished.

If you used an additional temporary Compose override during testing, include that override with the same project configuration for startup and cleanup. Relative bind sources are resolved from the first Compose file's directory; use absolute sources for certificate sets outside the standard lab directory.
