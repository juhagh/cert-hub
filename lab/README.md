# CertHub TLS Lab

A local Docker lab for demonstrating valid TLS connections and diagnosing certificate failures. Start with a valid server certificate, switch to an expired certificate, and compare curl's validation result with CertHub's diagnostic report.

The lab uses its own generated certificate authority (CA). You do not need to add this CA to your machine's system trust store.

## Prerequisites

- The .NET 10 SDK for the file-based generator and API.
- Docker with Docker Compose v2, with the Docker engine running.
- curl (`curl.exe` in Windows PowerShell).
- An interactive terminal for hidden password entry.
- Optional: OpenSSL for independent certificate inspection and verification. It is not required by the C# generator.

Check your tools:

```bash
dotnet --version
docker compose version
curl --version
```

The generator implements macOS, Linux and Windows branches using .NET cryptography APIs directly, without invoking Bash or OpenSSL. Generation, file permissions, failure cleanup and Docker loading have been manually verified on macOS. Windows and Linux execution have not yet been verified; cross-platform implementation is not a claim of completed validation on those systems.

Run the walkthrough from the repository root. Multiline commands below use Bash/zsh syntax; PowerShell users can enter the same commands on one line. Where shell-specific configuration differs, PowerShell alternatives are shown. Use `curl.exe` rather than a PowerShell alias.

## 1. Generate the certificates

```bash
dotnet run --file lab/tools/GenerateCertificates.cs -- lab/certificates/generated
```

The output directory is the app's single required argument. Relative paths resolve against the caller's working directory; absolute output paths are also supported. Its parent directory must already exist. The tool refuses existing output paths before prompting or generating keys, including existing symbolic links.

The tool prepares and verifies exports before writing eleven files into a uniquely named sibling staging directory. Only after writing succeeds does it move staging to the requested output path. File writes use create-new semantics; if publication fails, the tool attempts to clean up staging and reports any cleanup failure. It does not overwrite your previous lab material.

Stop running lab containers before moving an existing generated directory aside; retain it privately outside the repository if needed. Do not move private keys into an unignored repository folder. Output paths outside `lab/certificates/generated/` are not automatically covered by the repository's ignore rule.

If a run fails, inspect its error and any reported staging path. The tool cannot guarantee cleanup after forced termination or a machine crash. Inspect leftover staging privately before removing it; do not stage it in Git.

### Password prompts

The C# tool asks for two passwords, each entered twice for confirmation:

| Password | Protects | Used again for |
|---|---|---|
| PFX bundle password | `localhost.pfx`, `localhost-expired.pfx` and `client.pfx` | `CERTHUB_LAB_PFX_PASSWORD` for Compose |
| Standalone key password | CA, server and client encrypted PEM private-key exports | Decrypting those PEM keys for later inspection or signing |

Both passwords must be nonblank and match their confirmations. Input is hidden, and Backspace is supported. Redirected standard input is rejected because the tool requires an interactive terminal. Neither password is printed or written into source/configuration files.

The same confirmed PFX password is applied programmatically to all three bundles. Unlike the earlier shell workflow, you do not need to enter CA-key and server-key passphrases repeatedly during issuance: the keys are generated and used in memory, then their standalone exports are encrypted.

### Generated material

| File | Purpose |
|---|---|
| `certhub-lab-root-ca.cert.pem` | Public CA certificate supplied to clients for explicit trust |
| `certhub-lab-root-ca.key.pem` | Encrypted CA signing key |
| `localhost.key.pem` | Encrypted server private key shared by the two controlled lab certificates |
| `localhost.csr.pem` | Certificate signing request for `localhost` |
| `localhost.cert.pem` | Valid CA-issued server certificate |
| `localhost-expired.cert.pem` | Expired CA-issued server certificate |
| `localhost.pfx` | Valid server certificate and private key for the container |
| `localhost-expired.pfx` | Expired server certificate and private key for the container |
| `client.cert.pem` | CA-issued client certificate for mTLS |
| `client.key.pem` | Encrypted client private key |
| `client.pfx` | Client certificate and private key for curl |

Validity periods are calculated from one captured generation time:

| Certificate | Starts | Ends |
|---|---|---|
| Lab CA | Seven days before generation | 365 days after generation |
| Valid server | Five minutes before generation | 90 days after generation |
| Expired server | Two days before generation | One day before generation |
| Client | Five minutes before generation | 90 days after generation |

Both server certificates include `DNS:localhost`, server-authentication usage and `CA:FALSE`, with separate random serial numbers. The client certificate uses a separate key, client-authentication usage and `CA:FALSE`; it does not need a server hostname SAN. No `.srl` state file is needed.

The tool reloads all three PFX bundles with their password, checks that each has a private key and compares certificate fingerprints with the originals. It also decrypts all three encrypted PEM key exports and compares their public keys with the original keys. These checks verify the exports; they do not perform independent chain or hostname validation. The curl checks below exercise live validation. Optional OpenSSL checks are described in the scenario records.

On macOS, PFX reloading requires temporary keychain storage managed by .NET. Imported certificate objects are disposed when no longer needed. Windows and Linux use `EphemeralKeySet` for these verification imports.

The standard generated directory is excluded from Git and the Docker build context. On macOS/Linux, the directory is created with owner-only permissions (`700`), private-key files are created with mode `600`, and the public CA certificate and two server PFX bundles are explicitly set to `644` before publication so the container's non-root user can read them, including under `umask 077`. The client certificate, encrypted client key and client PFX remain owner-readable only (`600`); they are used on the host and are not mounted in the server. Windows uses inherited filesystem permissions rather than Unix modes. Do not commit generated material or use these lab keys outside this exercise.

## 2. Supply the PFX export password

In the terminal used for Compose, enter the export password without echoing it or placing its literal value in shell history:

```bash
printf 'Lab PFX export password: '
read -r -s CERTHUB_LAB_PFX_PASSWORD
printf '\n'
export CERTHUB_LAB_PFX_PASSWORD
```

This input sequence works in Bash and zsh. Use the confirmed PFX bundle password, not the standalone PEM-key password. The environment variable configures the lab server, not CertHub's probe trust. Repeat this step in a new terminal if needed.

PowerShell alternative:

```powershell
$pfxSecret = Read-Host 'Lab PFX export password' -AsSecureString
$env:CERTHUB_LAB_PFX_PASSWORD = [System.Net.NetworkCredential]::new('', $pfxSecret).Password
Remove-Variable pfxSecret
```

The resulting environment variable is a plain-text value passed to the local container; the secure prompt only hides interactive input.

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

For PowerShell, replace the root-path command with:

```powershell
$labRootCertificate = (Resolve-Path 'lab/certificates/generated/certhub-lab-root-ca.cert.pem').Path
dotnet user-secrets set "TlsProbe:RootCertificatePaths:0" "$labRootCertificate" --project src/CertHub.Api
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

## 7. Try mutual TLS

The [mutual TLS scenario](scenarios/05-mutual-tls.md) enables mandatory client certificates through `compose.mtls.yaml`. It demonstrates three cases: no client certificate, a trusted client certificate and a client certificate from a different CA.

Use a complete set from the current C# generator, including `client.pfx`. Earlier generated sets may lack client credentials. The public CA certificate must be readable by the container's non-root user; the current generator sets this permission. Keep private keys and client credentials on the host.

This is a lab capability. CertHub's diagnostic probe does not yet send a client certificate, and successful server validation alone cannot establish that an mTLS server accepted the client.

## Cleanup and regeneration

After recovery, stop the base service:

```bash
docker compose -f lab/compose.yaml down
```

If stopping while the expired or mTLS override is active, use the base file and that override with `down` instead. The PFX environment variable must remain set while Compose processes either configuration, including cleanup.

Stop the API with Ctrl+C. If the User Secrets values were added only for this exercise, remove them:

```bash
dotnet user-secrets remove "TlsProbe:TrustMode" --project src/CertHub.Api
dotnet user-secrets remove "TlsProbe:TrustConfigurationId" --project src/CertHub.Api
dotnet user-secrets remove "TlsProbe:RootCertificatePaths:0" --project src/CertHub.Api
unset CERTHUB_LAB_PFX_PASSWORD
```

In PowerShell, use `Remove-Item Env:CERTHUB_LAB_PFX_PASSWORD` instead of `unset`. After a curl command, inspect `$LASTEXITCODE` rather than `echo $?` to obtain its numeric exit code.

Remove any additional temporary root entries or probe overrides you added. Restart the API before testing restored configuration. With no other trust overrides, it returns to system trust.

Regeneration creates a new CA and new certificate fingerprints. Stop the lab before moving generated files aside and generating another set. Clients must use the newly generated root; the old CA cannot validate the replacement certificates. The examples above reuse the same file paths, but any copied CA certificates must also be updated.

## Scenario records

- [01 Valid server TLS](scenarios/01-valid-server-tls.md)
- [02 Untrusted certificate authority](scenarios/02-untrusted-ca.md)
- [03 Hostname mismatch](scenarios/03-hostname-mismatch.md)
- [04 Expired server certificate and recovery](scenarios/04-expired-server-certificate.md)
- [05 Mutual TLS](scenarios/05-mutual-tls.md)

Recorded timestamps and fingerprints describe earlier runs and will differ from newly generated material. Use the current generator rather than applying historical certificate dates to a newly generated CA.

## Earlier OpenSSL generator

`lab/scripts/generate-certificates.sh` remains available as the earlier, independently verified macOS shell workflow. It requires Bash and OpenSSL with explicit certificate-date support and has different password prompts. It does not generate the client credentials used by the mTLS scenario. It is not the default setup path, and its generated directory includes OpenSSL serial state. Do not run either generator over an existing output set.

## Planned learning notes

A future walkthrough will explain each artefact from key generation and CSR through signing, PFX packaging, deployment and verification, then compare this local lab with production PKI, renewal and key management.
