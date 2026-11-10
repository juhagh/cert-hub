# TLS diagnostics API

CertHub runs a TLS diagnostic against an explicitly allowed hostname and port, with enforced server validation and optional operator-configured client PFX credentials. It reports DNS resolution, TCP connectivity, TLS authentication and certificate-validation outcomes, preserving evidence collected before a failure.

The probe sends no HTTP request or other application data to the target. The HTTP API is the entry point that starts the diagnostic; it is separate from the target connection being inspected.

## Run locally

From the repository root, start the API using its HTTPS launch profile:

```bash
dotnet run --project src/CertHub.Api/CertHub.Api.csproj --launch-profile https
```

The current profile listens at `https://localhost:7297` and `http://localhost:5129`. Use the address printed by the application if your local settings differ. For HTTPS requests, trust the ASP.NET Core development certificate if needed:

```bash
dotnet dev-certs https --trust
```

This certificate protects requests to the CertHub API. It does not configure which certificates the diagnostic probe trusts.

The Development configuration allows `localhost:8443`. Start the Docker lab separately if using that target; its generated server certificate and PFX password must already be available:

```bash
docker compose -f lab/compose.yaml up --build -d
```

Compose requires the `CERTHUB_LAB_PFX_PASSWORD` environment variable. See the [valid server TLS scenario](../../lab/scenarios/01-valid-server-tls.md) for the lab setup and verification record.

## Request

`POST /diagnostics/tls`

```bash
curl --silent --show-error --include \
  https://localhost:7297/diagnostics/tls \
  -H 'Content-Type: application/json' \
  -d '{"hostname":"localhost","port":8443}'
```

| Field | Requirements |
|---|---|
| `hostname` | Required ASCII hostname, up to 253 characters. Each dot-separated label must contain 1–63 characters, start and end with a letter or digit, and otherwise contain letters, digits or hyphens. |
| `port` | Integer from 1 to 65535. |

Certificate paths, passwords and client credentials are not request fields. They are configured by the operator for the probe.

Single-label names such as `localhost` are accepted. IP literals, names containing only digits and dots, trailing dots, underscores, whitespace, schemes, paths and embedded ports are rejected. Unicode hostnames are not supported by this initial contract.

After syntax validation, the hostname and port must match one configured allowed-target entry. Hostname comparison is case-insensitive; the port must match exactly. Wildcards and hostname normalization are not supported.

## Responses

### 200 OK: diagnostic report

A `200` response means the API returned a diagnostic report. The target may have failed DNS resolution, TCP connection or TLS authentication. Inspect the individual outcomes and findings to determine what happened.

The following is an example from the local lab using system trust. The lab CA is not trusted under that configuration, so certificate validation and TLS authentication fail while certificate evidence remains available:

```json
{
  "hostname": "localhost",
  "port": 8443,
  "attemptedAt": "2026-10-20T03:44:56.287209+00:00",
  "dnsResolution": "Passed",
  "tcpConnection": "Passed",
  "tlsAuthentication": "Failed",
  "certificateValidation": "Failed",
  "connection": {
    "remoteIpAddress": "127.0.0.1",
    "tcpConnectDuration": "00:00:00.0015316",
    "tlsProtocol": null,
    "cipherSuite": null,
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
    "mode": "System",
    "configurationId": "system",
    "rootSha256Fingerprints": [],
    "evaluationTime": "2026-10-20T03:44:56.287209+00:00"
  },
  "findings": [
    {
      "code": "TCP_CONNECTION_FAILED",
      "message": "::1 - ConnectionRefused: Connection refused"
    },
    {
      "code": "CERT_CHAIN_INVALID",
      "message": "Chain validation failed under the configured policy. [PartialChain: One or more certificates required to validate this certificate cannot be found.]"
    },
    {
      "code": "TLS_AUTHENTICATION_FAILED",
      "message": "The remote certificate was rejected by the provided RemoteCertificateValidationCallback."
    }
  ]
}
```

Outcomes are serialized as `Passed`, `Failed` or `NotEvaluated`. A later stage is not evaluated when the connection cannot reach it. Certificate-validation evidence can still be available when TLS authentication fails.

Connection and certificate fields reflect available evidence. The certificate can be `null`; negotiated protocol and cipher suite are populated only after successful TLS authentication. ALPN is not currently configured by the probe, so `applicationProtocol` remains `null`.

A failed address attempt can produce a finding even when a later address connects successfully. In the example, IPv6 failed before IPv4 succeeded. `tcpConnectDuration` measures the TCP stage, including earlier address attempts, rather than only the successful attempt.

Use finding codes for identification and messages for explanatory details. Platform error wording and chain-status details can vary. See the [diagnostic report design](../architecture/diagnostic-report.md) for the report model.

### Client authentication and report interpretation

`certificateValidation` and `certificate` describe the server certificate. The probe validates that certificate independently of any client credential it supplies.

`tlsAuthentication: Passed` means `AuthenticateAsClientAsync` completed successfully from the probe's perspective. It does not establish that the remote server accepted the client certificate or granted application access. A configured certificate is available for selection; configuration alone does not prove it was sent.

Depending on protocol, platform and timing, server rejection of a missing or untrusted client certificate may become observable only during subsequent communication. The current probe returns after authentication and sends no application data. A report can therefore show client-side TLS completion while the server rejects client authentication. The report does not currently contain client-certificate presentation or remote-acceptance evidence.

Controlled integration tests observe the server directly to confirm presentation, acceptance and rejection. Those observations are not available to the production API. See the [report design](../architecture/diagnostic-report.md) for the precise outcome definitions.

### Certificate validity findings

When a server certificate is available, CertHub compares its validity dates with `trustContext.evaluationTime`, the same timestamp used for the chain policy's verification time.

| Finding code | Condition | Message |
|---|---|---|
| `CERT_EXPIRED` | Evaluation time is after the certificate's `notAfter`. | The server certificate has expired. |
| `CERT_NOT_YET_VALID` | Evaluation time is before the certificate's `notBefore`. | The server certificate is not yet valid. |

Equality at either boundary produces no date-based finding. A certificate within its validity window can still fail validation for another reason, such as hostname mismatch or an untrusted chain. No date-based finding is produced when certificate evidence is unavailable.

These findings describe the server certificate, not the validity of every certificate in its chain. They supplement `CERT_CHAIN_INVALID` and its platform details rather than replacing them. For example, an expired server certificate can produce `CERT_EXPIRED`, a `CERT_CHAIN_INVALID` finding containing `NotTimeValid`, and `TLS_AUTHENTICATION_FAILED`.

TLS acceptance remains governed by certificate validation. The date evaluator adds explanations without overriding the validation callback's decision. Clients can use the dedicated codes to distinguish server certificate expiry from a certificate that has not yet become valid, without parsing platform error messages.

### 400 Bad Request: invalid input

Invalid fields produce a validation problem response. For an empty hostname and port `0`:

```json
{
  "type": "https://tools.ietf.org/html/rfc9110#section-15.5.1",
  "title": "One or more validation errors occurred.",
  "status": 400,
  "errors": {
    "Hostname": ["Hostname cannot be empty"],
    "Port": ["Port must be between 1 and 65535."]
  }
}
```

A syntactically valid target outside the allowlist also returns `400`, with:

```json
{
  "Target": ["The requested hostname and port are not allowed."]
}
```

This object is the `errors` property of the validation problem response. Rejected requests do not invoke the probe.

## Target configuration

Configure allowed hostname-and-port pairs under `DiagnosticTargets`:

```json
{
  "DiagnosticTargets": {
    "AllowedTargets": [
      {
        "Hostname": "localhost",
        "Port": 8443
      }
    ]
  }
}
```

The base configuration has an empty allowlist, which denies all targets. Development configuration permits `localhost:8443`. Allowing a target does not make its certificate trusted.

## Trust and timeout configuration

The probe reads the `TlsProbe` section. Its default trust mode is `System` and its default network diagnostic timeout is ten seconds. The configured timeout must be greater than zero and no more than sixty seconds.

### Local lab settings with User Secrets

Keep `appsettings.Development.json` tracked for shared development defaults. Configure machine-specific lab trust settings through .NET User Secrets instead of adding local certificate paths to that file.

The API project includes a tracked `UserSecretsId`. You do not need to run `dotnet user-secrets init` again. The identifier associates the project with a local configuration store; the values are stored outside the repository and are not shared by Git. Each developer configures their own values. User Secrets are not encrypted and are intended for development configuration, not production credential storage.

Run from the repository root, replacing the example path with your actual absolute path before executing:

```bash
dotnet user-secrets set "TlsProbe:TrustMode" "CustomRoots" --project src/CertHub.Api
dotnet user-secrets set "TlsProbe:TrustConfigurationId" "certhub-lab" --project src/CertHub.Api
dotnet user-secrets set "TlsProbe:RootCertificatePaths:0" \
  "/absolute/path/to/CertHub/lab/certificates/generated/certhub-lab-root-ca.cert.pem" \
  --project src/CertHub.Api
```

The final `:0` identifies the first item in `RootCertificatePaths`. These commands use the default ten-second timeout; no timeout override is needed for this scenario.

The API's standard configuration loads User Secrets automatically in Development, after the appsettings files. Environment variables and command-line settings can still override them. The HTTPS launch profile selects Development. Start or restart the API after changing these values:

```bash
dotnet run --project src/CertHub.Api/CertHub.Api.csproj --launch-profile https
```

Check a diagnostic report for `trustContext.mode` equal to `CustomRoots` and `configurationId` equal to `certhub-lab`. Allowlisting remains a separate setting; Development already permits `localhost:8443`.

### Custom-root requirements

Replace the example path with an existing certificate file accessible to the API process. Custom-root mode requires a nonempty configuration identifier other than `system`, and at least one nonblank certificate path. Every configured file must load successfully. The loader accepts a PEM or DER certificate file; private keys are not required. Relative paths resolve against the process working directory.

In custom-root mode, the supplied roots define the trust anchors for the check. In system mode, the report identifies the configuration as `system`; an empty root-fingerprint list does not mean the system trust store is empty.

Certificate validation remains enforced in both modes. Revocation checking and automatic downloads of missing issuer certificates are disabled. A successful result therefore means acceptance under this configured policy, not a complete assessment of every certificate risk.

One shared timeout covers the network diagnostic stages. The budget starts after client PFX loading. Synchronous certificate-file loading is not cancellable through this timeout. Timeout outcomes are returned as diagnostic reports. Caller cancellation propagates instead of being converted into a target failure. Configuration errors and unexpected application errors are not diagnostic results; the API does not yet define a dedicated response contract for them.

### Optional client PFX configuration

Client credentials are separate from server trust and target allowlisting. To check the mTLS lab, the probe must trust the lab server's CA, and the server must trust the CA that issued the supplied client credential.

| Option | Meaning |
|---|---|
| `TlsProbe:ClientCertificatePath` | Optional PFX path accessible to the API process. Null means no client credential is configured. Empty or whitespace paths are rejected. Relative paths resolve against the process working directory. |
| `TlsProbe:ClientCertificatePassword` | Password used to load that PFX. Null or empty is permitted for a passwordless PFX. A non-null password without a configured path is rejected. |

The loaded PFX must contain a certificate with a private key. Loading and the private-key check occur before networking. The probe owns and disposes the imported certificate for each attempt. Missing or unreadable files, incorrect passwords and a missing private key are local configuration errors; they propagate as exceptions rather than target findings. The API currently has no dedicated response contract for these errors.

For local development, set the path through User Secrets, replacing this example with the actual absolute path:

```bash
dotnet user-secrets set "TlsProbe:ClientCertificatePath" \
  "/absolute/path/to/CertHub/lab/certificates/generated/client.pfx" \
  --project src/CertHub.Api
```

Keep the password out of tracked settings. The lab generator uses the same confirmed PFX password for its client and server bundles. In the terminal where you will start the API, after supplying `CERTHUB_LAB_PFX_PASSWORD` as described in the [lab setup guide](../../lab/README.md), Bash/zsh users can pass it to the probe through configuration:

```bash
export TlsProbe__ClientCertificatePassword="${CERTHUB_LAB_PFX_PASSWORD:?Set the lab PFX password first}"
```

PowerShell equivalent, after setting the lab password in that terminal:

```powershell
if ([string]::IsNullOrEmpty($env:CERTHUB_LAB_PFX_PASSWORD)) { throw 'Set the lab PFX password first' }
$env:TlsProbe__ClientCertificatePassword = $env:CERTHUB_LAB_PFX_PASSWORD
```

These commands reuse an existing environment value without placing the literal password in command history. Environment values remain plain text. Set the variable in the API's launching terminal; setting it only in a different Compose terminal does not configure the API. If the PFX uses a different password, supply its actual password through your local configuration instead.

After configuring custom-root server trust as shown above, enable the lab's mTLS mode from the repository root:

```bash
docker compose -f lab/compose.yaml -f lab/compose.mtls.yaml up --build -d
```

Start or restart the API from the terminal containing its password setting:

```bash
dotnet run --project src/CertHub.Api/CertHub.Api.csproj --launch-profile https
```

Call `POST /diagnostics/tls` with the same hostname-and-port request as before. A trusted client credential enables the authentication attempt; the response's TLS outcome still has the client-side interpretation described above. No additional client-authentication outcome is returned. For the independently observed Docker/curl acceptance and rejection cases, see the [mTLS lab scenario](../../lab/scenarios/05-mutual-tls.md).

The single configured client credential is available on all allowed diagnostic attempts. This milestone does not provide per-target credential selection or accept credentials from API callers.

To return to probing without a client credential, remove both settings from every configuration source you used. For the User Secrets path and environment password shown here:

```bash
dotnet user-secrets remove "TlsProbe:ClientCertificatePath" --project src/CertHub.Api
unset TlsProbe__ClientCertificatePassword
```

In PowerShell, replace `unset` with `Remove-Item Env:TlsProbe__ClientCertificatePassword`. If you also set the password through User Secrets, remove `TlsProbe:ClientCertificatePassword` there. Restart the API after cleanup. Server trust settings are independent and can remain in place.

Stop the mTLS lab while its PFX password is still configured:

```bash
docker compose -f lab/compose.yaml -f lab/compose.mtls.yaml down
```

### Return to default system trust

If these settings were added only for the lab, remove the three overrides after the scenario, including any additional root-array entries you added:

```bash
dotnet user-secrets remove "TlsProbe:TrustMode" --project src/CertHub.Api
dotnet user-secrets remove "TlsProbe:TrustConfigurationId" --project src/CertHub.Api
dotnet user-secrets remove "TlsProbe:RootCertificatePaths:0" --project src/CertHub.Api
```

Remove any other temporary `TlsProbe` overrides you set for this exercise, then restart the API. With no custom-root settings supplied by other configuration sources, the probe returns to its default system trust. Check that the report shows `System` and configuration ID `system`. This changes the probe's trust policy; it does not remove certificates from the operating system trust store.

API User Secrets and `TlsProbe__...` environment values configure the probe. Docker Compose independently obtains the lab server's PFX password from `CERTHUB_LAB_PFX_PASSWORD` in its calling environment.

## Current deployment scope

This milestone is intended for controlled local targets. The API has no authentication or rate limiting. Its exact hostname-and-port allowlist does not restrict resolved IP addresses and is not a complete policy for exposing a network diagnostic service publicly. Deployment hardening is a separate milestone.

## Verification

Endpoint integration tests use an in-process API and a stub probe to verify invalid input, denied targets and successful report responses, including enum serialization and probe invocation. Separate probe integration tests exercise real loopback TCP/TLS connections with temporary certificates, custom trust, validation failures, cancellation, timeouts and invalid configuration. Expired and not-yet-valid server certificate tests verify the dedicated validity findings while retaining certificate evidence and chain-validation details. Domain tests use fixed timestamps to verify the date rules, including equality at both validity boundaries.

```bash
dotnet test tests/CertHub.Domain.Tests/CertHub.Domain.Tests.csproj
dotnet test tests/CertHub.IntegrationTests/CertHub.IntegrationTests.csproj
```

Client credential tests cover invalid configuration, missing private keys and incorrect PFX passwords. Loopback mTLS tests verify successful authentication with protected, empty-password and null-password PFX exports, using the server-observed authenticated fingerprint. Negative tests verify server rejection without a credential and with a presented certificate from another CA; the latter also checks its presented fingerprint. Client-side TLS failure timing is not required to match across platforms.

These tests require neither Docker nor changes to the machine's trust store.
