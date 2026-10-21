# TLS diagnostics API

CertHub runs a server TLS diagnostic against an explicitly allowed hostname and port. It reports DNS resolution, TCP connectivity, TLS authentication and certificate-validation outcomes, preserving evidence collected before a failure.

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

The probe reads the `TlsProbe` section. Its default trust mode is `System` and its default overall timeout is ten seconds. The configured timeout must be greater than zero and no more than sixty seconds.

For the lab, custom-root trust can be configured with the root CA's public certificate:

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

Replace the example path with an existing certificate file accessible to the API process. Custom-root mode requires a nonempty configuration identifier other than `system`, and at least one nonblank certificate path. Every configured file must load successfully. The loader accepts a PEM or DER certificate file; private keys are not required. Relative paths resolve against the process working directory.

In custom-root mode, the supplied roots define the trust anchors for the check. In system mode, the report identifies the configuration as `system`; an empty root-fingerprint list does not mean the system trust store is empty.

Certificate validation remains enforced in both modes. Revocation checking and automatic downloads of missing issuer certificates are disabled. A successful result therefore means acceptance under this configured policy, not a complete assessment of every certificate risk.

One shared timeout covers the diagnostic stages. Timeout outcomes are returned as diagnostic reports. Caller cancellation propagates instead of being converted into a target failure. Configuration errors and unexpected application errors are not diagnostic results; the API does not yet define a dedicated response contract for them.

## Current deployment scope

This milestone is intended for controlled local targets. The API has no authentication or rate limiting. Its exact hostname-and-port allowlist does not restrict resolved IP addresses and is not a complete policy for exposing a network diagnostic service publicly. Deployment hardening is a separate milestone.

## Verification

Endpoint integration tests use an in-process API and a stub probe to verify invalid input, denied targets and successful report responses, including enum serialization and probe invocation. Separate probe integration tests exercise real loopback TCP/TLS connections with temporary certificates, custom trust, validation failures, cancellation, timeouts and invalid configuration.

```bash
dotnet test tests/CertHub.IntegrationTests/CertHub.IntegrationTests.csproj
```

These tests require neither Docker nor changes to the machine's trust store.
