# CertHub TLS Lab

A local Docker lab for demonstrating valid TLS connections and diagnosing certificate failures. Start with a valid server certificate, switch to an expired certificate, and compare curl's validation result with CertHub's diagnostic report.

The lab uses its own generated certificate authority (CA). You do not need to add this CA to your machine's system trust store.

## Prerequisites

- macOS or Linux with Bash.
- OpenSSL supporting `openssl x509 -not_before` and `-not_after`. The generator checks these capabilities; OpenSSL 3.6 was used for the verified macOS run. macOS's bundled `openssl` may not support them, so ensure a compatible installation is on `PATH`.
- Docker with Docker Compose v2, with the Docker engine running.
- curl.
- The .NET 10 SDK if you also want to run the CertHub API on the host.

Check your tools:

```bash
openssl version
docker compose version
curl --version
dotnet --version
```

The commands below run from the repository root. The certificate generator itself can be invoked from any working directory. Its date helper supports macOS and Linux; the end-to-end bootstrap has been manually verified on macOS with Docker Desktop.

## 1. Generate the certificates

```bash
bash lab/scripts/generate-certificates.sh
```

The script creates `lab/certificates/generated/` and refuses to reuse an existing file, directory or symbolic link at that path. It does not overwrite your previous lab material. Stop running lab containers before moving an existing generated directory aside; retain it privately outside the repository if you need it later. Do not move private keys into a new, unignored repository folder.

If generation fails, inspect the error and retain the partial output for diagnosis. A subsequent run will refuse that directory too. Move it aside before retrying rather than mixing old and new files.

### Password prompts

There are three distinct password roles:

| Password | When to choose it | Where it is used again |
|---|---|---|
| CA private-key passphrase | First encrypted key-generation step | Creating the self-signed CA certificate and signing each server certificate |
| Server private-key passphrase | Second encrypted key-generation step | Creating the CSR and exporting both PFX bundles |
| PFX export password | First PFX export | Choose the same value during the second export; supply it to Docker Compose |

The script labels each stage. OpenSSL asks for confirmation when choosing a new password. Passwords are entered interactively and are not written into the script. The script asks you to use the same export password for both bundles but does not enforce equality between them.

### Generated material

| File | Purpose |
|---|---|
| `certhub-lab-root-ca.cert.pem` | Public CA certificate supplied to clients for explicit trust |
| `certhub-lab-root-ca.key.pem` | Encrypted CA signing key |
| `certhub-lab-root-ca.cert.srl` | Serial state used during certificate issuance |
| `localhost.key.pem` | Encrypted server private key shared by the two controlled lab certificates |
| `localhost.csr.pem` | Certificate signing request for `localhost` |
| `localhost.cert.pem` | Valid CA-issued server certificate |
| `localhost-expired.cert.pem` | Expired CA-issued server certificate |
| `localhost.pfx` | Valid server certificate and private key for the container |
| `localhost-expired.pfx` | Expired server certificate and private key for the container |

Validity periods are calculated from one captured generation time:

| Certificate | Starts | Ends |
|---|---|---|
| Lab CA | Seven days before generation | 365 days after generation |
| Valid server | Five minutes before generation | 90 days after generation |
| Expired server | Two days before generation | One day before generation |

Both server certificates include `DNS:localhost`, server-authentication usage and `CA:FALSE`. The script verifies acceptance of the valid certificate and requires the expired certificate to fail with the expected server-certificate expiry error.

Generated files are excluded from Git and the Docker build context. The output directory is private (`700`), standalone private keys remain `600`, and password-protected PFX bundles are made readable (`644`) for the container's non-root user. Do not commit generated material or use these lab keys outside this exercise.

## 2. Supply the PFX export password

In the terminal used for Compose, enter the export password without echoing it or placing its literal value in shell history:

```bash
printf 'Lab PFX export password: '
read -r -s CERTHUB_LAB_PFX_PASSWORD
printf '\n'
export CERTHUB_LAB_PFX_PASSWORD
```

This input sequence works in Bash and zsh. Use a nonempty password matching both PFX files. The environment variable configures the lab server, not CertHub's probe trust. Repeat this step in a new terminal if needed.

## 3. Start and verify valid TLS

```bash
docker compose -f lab/compose.yaml config --quiet
docker compose -f lab/compose.yaml up --build -d
docker compose -f lab/compose.yaml logs tls-server
```

After the server is listening, verify it using the generated CA:

```bash
curl --verbose --noproxy '*' \
  --cacert lab/certificates/generated/certhub-lab-root-ca.cert.pem \
  https://localhost:8443/
```

Expected: certificate verification succeeds, `localhost` matches the certificate, and the server returns HTTP `200` with `Hello World!`.

The service is published on IPv4 loopback only. curl may first report a refused connection to `::1`, then connect successfully to `127.0.0.1`. That earlier TCP failure is separate from TLS validation.

## 4. Inspect the target through CertHub

The API runs on the host for this walkthrough. Development already allows `localhost:8443` as a diagnostic target. Configure its trust through User Secrets, keeping machine-specific paths outside tracked settings:

```bash
dotnet user-secrets set "TlsProbe:TrustMode" "CustomRoots" --project src/CertHub.Api
dotnet user-secrets set "TlsProbe:TrustConfigurationId" "certhub-lab" --project src/CertHub.Api
dotnet user-secrets set "TlsProbe:RootCertificatePaths:0" \
  "$(pwd)/lab/certificates/generated/certhub-lab-root-ca.cert.pem" \
  --project src/CertHub.Api
```

The project already includes a `UserSecretsId`; initialization is unnecessary. User Secrets load automatically in Development and are not encrypted. Existing environment or command-line overrides can take precedence.

Trust the separate ASP.NET Core development certificate if needed, then start the API:

```bash
dotnet dev-certs https --trust
dotnet run --project src/CertHub.Api/CertHub.Api.csproj --launch-profile https
```

In another terminal:

```bash
curl --silent --show-error --http1.1 --noproxy '*' \
  -X POST https://localhost:7297/diagnostics/tls \
  -H 'Content-Type: application/json' \
  -d '{"hostname":"localhost","port":8443}' \
  -w '\nHTTP status: %{http_code}\n'
```

Expected: HTTP `200` with all four diagnostic stages `Passed`, custom-root trust recorded and certificate evidence present. A finding about the initial IPv6 refusal may remain even though the TCP stage succeeds over IPv4.

There are two independent TLS connections: curl trusts the API's development certificate on port `7297`; CertHub trusts the lab CA when probing port `8443`. The API request above uses HTTP/1.1 to avoid an HTTP/2 connection-shutdown issue observed locally on macOS; this does not change the probe's target TLS policy.

CertHub sends no HTTP request to the target. HTTP `200` from the API indicates report delivery; inspect its stage outcomes to assess the target. See the [API guide](../docs/api/tls-diagnostics.md) for the response contract and configuration details.

## 5. Switch to the expired certificate

Keep the same PFX password and client trust settings. Select the override:

```bash
docker compose \
  -f lab/compose.yaml \
  -f lab/compose.expired.yaml \
  config --quiet

docker compose \
  -f lab/compose.yaml \
  -f lab/compose.expired.yaml \
  up -d
```

Repeat the curl check from step 3, followed immediately by `echo $?`. Expected: `certificate has expired` and exit code `60`.

Repeat the API request from step 4. Expected: DNS and TCP `Passed`; TLS authentication and certificate validation `Failed`; findings including `CERT_EXPIRED`, `CERT_CHAIN_INVALID` and `TLS_AUTHENTICATION_FAILED`. Certificate evidence remains available. The API still returns HTTP `200` because diagnosis completed.

## 6. Restore the valid certificate

Stop the expired configuration and restart the base service:

```bash
docker compose \
  -f lab/compose.yaml \
  -f lab/compose.expired.yaml \
  down

docker compose -f lab/compose.yaml up -d
```

Repeat the API request without changing its trust settings. All four stages should pass again, provided the valid certificate remains within its validity period. This demonstrates that replacing the server certificate resolves the failure.

## Cleanup and regeneration

After recovery, stop the base service:

```bash
docker compose -f lab/compose.yaml down
```

If stopping while the expired override is active, use both Compose files with `down` instead. The PFX environment variable must remain set while Compose processes either configuration, including cleanup.

Stop the API with Ctrl+C. If the User Secrets values were added only for this exercise, remove them:

```bash
dotnet user-secrets remove "TlsProbe:TrustMode" --project src/CertHub.Api
dotnet user-secrets remove "TlsProbe:TrustConfigurationId" --project src/CertHub.Api
dotnet user-secrets remove "TlsProbe:RootCertificatePaths:0" --project src/CertHub.Api
unset CERTHUB_LAB_PFX_PASSWORD
```

Remove any additional temporary root entries or probe overrides you added. Restart the API before testing restored configuration. With no other trust overrides, it returns to system trust.

Regeneration creates a new CA and new certificate fingerprints. Stop the lab before moving generated files aside and generating another set. Clients must use the newly generated root; the old CA cannot validate the replacement certificates. The examples above reuse the same file paths, but any copied CA certificates must also be updated.

## Scenario records

- [01 Valid server TLS](scenarios/01-valid-server-tls.md)
- [02 Untrusted certificate authority](scenarios/02-untrusted-ca.md)
- [03 Hostname mismatch](scenarios/03-hostname-mismatch.md)
- [04 Expired server certificate and recovery](scenarios/04-expired-server-certificate.md)

Recorded timestamps and fingerprints describe earlier runs and will differ from newly generated material. Some scenario records contain historical issuance commands; use this bootstrap to generate a current certificate set rather than applying those historical dates to a new CA.
