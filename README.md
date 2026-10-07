# CertHub

CertHub is a .NET application for investigating TLS connectivity failures between services. It is motivated by production troubleshooting experience where certificate expiry, trust configuration and certificate selection made connection failures difficult to diagnose.

The first milestone is an API that checks an HTTPS endpoint and reports certificate information, validation findings and connection errors. Support for client certificates will extend these diagnostics to mutual TLS (mTLS).

## TLS and mTLS Lab

A deliberately breakable, containerised lab accompanies the application. It provides reproducible scenarios for exploring successful connections and failures such as untrusted certificate authorities, hostname mismatches and expired certificates.

## Project Status

Early development. The solution structure is in place and targets .NET 10. Diagnostic functionality has not yet been implemented.

## Planned Development

- On-demand TLS diagnostics with clear findings and supporting evidence.
- Client certificate support for mTLS diagnostics.
- Scheduled monitoring and certificate expiry alerts.
- Azure deployment with automated delivery and operational logging.

## Structure

- `src/` — API, application, domain and infrastructure projects.
- `tests/` — domain, application and integration tests.
- `lab/` — test services, certificate-generation assets and diagnostic scenarios.
- `docs/` — architecture documentation and decision records.