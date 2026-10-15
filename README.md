# CertHub

CertHub is a .NET 10 application for investigating TLS connectivity failures between services. It is motivated by operational troubleshooting challenges where certificate expiry, trust configuration and uncertainty about the certificate a service actually uses make failures difficult to diagnose.

The goal is to report what a connection attempt observed: which stages succeeded, where it failed, and what certificate and connection evidence remains available.

## Current Status

Active development. The core TLS probe is implemented and exercised through integration tests. The HTTP diagnostic endpoint has not yet been implemented; the API project currently contains template scaffolding.

The probe currently supports:

- DNS resolution and sequential TCP connection attempts across resolved addresses.
- Server TLS authentication with certificate validation enforced against system trust or explicitly configured custom roots.
- Diagnostic reports distinguishing DNS, TCP, TLS authentication and certificate-validation outcomes.
- Certificate subject, issuer, validity dates and SHA-256 fingerprint capture, including when validation rejects the certificate.
- Hostname and certificate-chain validation findings, with supporting platform error details.
- Connected IP address, TCP-stage duration and negotiated TLS protocol and cipher suite when authentication succeeds.
- A shared diagnostic timeout and propagation of caller cancellation.

Revocation checking and automatic downloads of missing issuer certificates are disabled for this initial milestone. The probe sends no HTTP request or other application data to the target.

## Tests

Self-contained integration tests currently cover:

- Rejection of an untrusted server certificate while preserving certificate evidence.
- Cancellation before a diagnostic attempt starts.
- Caller cancellation during an active TLS authentication attempt.
- Timeout reporting when the shared diagnostic budget expires during TLS authentication. 
- Successful TLS authentication using a configured custom root CA.

Tests use in-process loopback servers, dynamically assigned ports and temporary certificates. They do not require Docker, externally hosted services or changes to the machine's trust store.

Additional DNS, TCP and TLS failure paths need dedicated verification.

## Build and Test

Prerequisite: the .NET 10 SDK.

Run from the repository root:

```bash
dotnet build
dotnet test tests/CertHub.IntegrationTests/CertHub.IntegrationTests.csproj
```

## TLS Lab

A separate Docker-based lab provides controlled scenarios for learning and investigating TLS behaviour:

- [Valid server TLS](lab/scenarios/01-valid-server-tls.md)
- [Untrusted certificate authority](lab/scenarios/02-untrusted-ca.md)
- [Hostname mismatch](lab/scenarios/03-hostname-mismatch.md)

The lab uses a locally generated root CA and server certificate. Generated certificates, private keys and PFX files are excluded from Git and from the Docker build context. The server certificate is mounted read-only at runtime, and its password is supplied through an environment variable.

The lab is separate from the integration-test servers. Expired-certificate and mTLS scenarios are planned.

## Architecture

The solution separates diagnostic contracts, use-case orchestration and networking implementation:

| Project | Responsibility |
|---|---|
| `CertHub.Domain` | Diagnostic report types, outcomes and findings |
| `CertHub.Application` | Diagnostic request, use case and TLS probe interface |
| `CertHub.Infrastructure` | DNS, TCP, TLS probing and certificate evidence extraction |
| `CertHub.Api` | Future HTTP entry point and dependency composition |

The product projects do not reference the lab server.

Design documentation:

- [Architecture overview](docs/architecture/overview.md)
- [Application structure decision](docs/decisions/0001-application-structure.md)
- [Diagnostic report design](docs/architecture/diagnostic-report.md)

## Next Steps

- Expand DNS, TCP and TLS failure-path coverage.
- Expose the diagnostic use case through an HTTP endpoint with request validation and target restrictions.
- Automate build and test checks in GitHub Actions.

Later milestones include mTLS diagnostics, persistent history, scheduled monitoring, expiry alerts and Azure deployment.

## Repository Structure

- `src/` — domain, application, infrastructure and API projects.
- `tests/` — test projects and self-contained TLS test servers.
- `lab/` — Docker lab server, certificate configuration and diagnostic scenarios.
- `docs/` — architecture documentation and decision records.
