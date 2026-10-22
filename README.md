# CertHub

CertHub is a .NET 10 application for investigating TLS connectivity failures between services. It is motivated by operational troubleshooting challenges where certificate expiry, trust configuration and uncertainty about the certificate a service actually uses make failures difficult to diagnose.

The goal is to report what a connection attempt observed: which stages succeeded, where it failed, and what certificate and connection evidence remains available.

## Current Status

Active development. The server TLS probe is available through `POST /diagnostics/tls`, with request validation and an explicit hostname-and-port allowlist. This milestone is intended for controlled local targets.

Current capabilities include:

- DNS resolution and sequential TCP connection attempts across resolved addresses.
- Server TLS authentication with enforced certificate validation using system trust or configured custom root CAs.
- Reports distinguishing DNS, TCP, TLS authentication and certificate-validation outcomes.
- Certificate subject, issuer, validity dates and SHA-256 fingerprint capture, including when validation rejects the certificate.
- Hostname and certificate-chain validation findings with supporting platform error details.
- Connected IP address, TCP-stage duration and negotiated TLS protocol and cipher suite when authentication succeeds.
- A shared diagnostic timeout and propagation of caller cancellation.
- HTTP request validation, target-policy enforcement and readable enum values in JSON responses.

The probe sends no HTTP request or other application data to the target. Revocation checking and automatic downloads of missing issuer certificates are disabled for this milestone.

A diagnostic response can return HTTP `200` while reporting a failed target connection. The status indicates that a report was returned; the report's outcomes describe the target.

## Build and Test

Prerequisite: the .NET 10 SDK.

Run from the repository root:

```bash
dotnet restore CertHub.slnx
dotnet build CertHub.slnx --no-restore
dotnet test tests/CertHub.IntegrationTests/CertHub.IntegrationTests.csproj
```

The integration suite currently contains 65 test cases, all passing in the latest local run. Tests cover DNS resolution failure, TCP connection refusal, probe configuration, certificate validation and evidence preservation, custom-root trust, cancellation, timeouts, request validation, target policy and HTTP endpoint behaviour.

Most tests use in-process API hosting, loopback servers, dynamically assigned ports and temporary certificates. Endpoint tests use a stub probe; connection tests exercise real TCP/TLS behaviour. Tests do not require Docker or changes to the machine's trust store.

The DNS failure test resolves `does-not-exist.invalid` through the operating system's name resolver. It depends on the machine's resolution configuration and timing, including local hosts entries, caches and configured DNS servers. It does not necessarily make an external DNS query or require an internet connection. This test is therefore environment-dependent rather than fully isolated.

GitHub Actions restores, builds and runs the integration suite in Release configuration on Ubuntu for pull requests targeting `main` and pushes to `main`.

## Run the API

```bash
dotnet run --project src/CertHub.Api/CertHub.Api.csproj --launch-profile https
```

The current HTTPS launch profile uses `https://localhost:7297`. Trust the ASP.NET Core development certificate if needed with `dotnet dev-certs https --trust`.

Development configuration permits the target `localhost:8443`; the base configuration denies all targets. With the lab running:

```bash
curl --silent --show-error --include \
  https://localhost:7297/diagnostics/tls \
  -H 'Content-Type: application/json' \
  -d '{"hostname":"localhost","port":8443}'
```

The default probe uses system trust, so rejection of the locally issued lab certificate is expected unless its CA is trusted under the configured policy. Allowing a target and trusting its certificate are separate settings.

See the [TLS diagnostics API guide](docs/api/tls-diagnostics.md) for request rules, response examples, allowlist configuration, custom-root trust and timeout behaviour.

The API currently has no authentication or rate limiting. Its hostname-and-port allowlist does not restrict resolved IP addresses. Public deployment requires further access controls and network-target policy.

## TLS Lab

A separate Docker-based lab provides controlled scenarios for learning and investigating TLS behaviour:

- [Valid server TLS](lab/scenarios/01-valid-server-tls.md)
- [Untrusted certificate authority](lab/scenarios/02-untrusted-ca.md)
- [Hostname mismatch](lab/scenarios/03-hostname-mismatch.md)

The lab uses a locally generated root CA and server certificate. Generated certificates, private keys and PFX files are excluded from Git and the Docker build context. The server certificate is mounted read-only at runtime, and its password is supplied through the `CERTHUB_LAB_PFX_PASSWORD` environment variable.

Once the generated certificate and password are available, start the lab from the repository root:

```bash
docker compose -f lab/compose.yaml up --build -d
```

The lab is separate from the integration-test servers. Expired-certificate and mTLS lab scenarios are planned.

## Architecture

The solution separates diagnostic contracts, use-case orchestration and networking implementation:

| Project | Responsibility |
|---|---|
| `CertHub.Domain` | Diagnostic report types, outcomes and findings |
| `CertHub.Application` | Diagnostic request, use case and TLS probe interface |
| `CertHub.Infrastructure` | DNS, TCP, TLS probing and certificate evidence extraction |
| `CertHub.Api` | HTTP endpoint, request validation, target policy and dependency composition |

The product projects do not reference the lab server.

Design documentation:

- [Architecture overview](docs/architecture/overview.md)
- [Application structure decision](docs/decisions/0001-application-structure.md)
- [Diagnostic report design](docs/architecture/diagnostic-report.md)
- [TLS diagnostics API](docs/api/tls-diagnostics.md)

## Next Steps

- Expand DNS and TCP failure-path coverage, including deterministic resolver tests and address fallback.
- Improve diagnostic evidence and report presentation as further scenarios are added.
- Define access controls and resolved-address restrictions before broader deployment.

Later milestones include mTLS diagnostics, persistent history, scheduled monitoring, expiry alerts and Azure deployment.

## Repository Structure

- `src/` — domain, application, infrastructure and API projects.
- `tests/` — test projects and self-contained TLS test servers.
- `lab/` — Docker lab server, certificate configuration and diagnostic scenarios.
- `docs/` — API guides, architecture documentation and decision records.
