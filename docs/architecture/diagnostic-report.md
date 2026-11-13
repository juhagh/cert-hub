# Diagnostic Report Design

## Purpose

CertHub reports the outcome of a TLS connection attempt and the evidence available to explain it.

A failed connection is an expected diagnostic result. The report distinguishes observed failures from possible causes
and preserves evidence gathered before failure.

## Current Scope

CertHub checks a DNS hostname and port, such as `localhost:8443`, without sending an HTTP request or other application data.

The probe optionally loads an operator-configured client PFX for TLS client authentication. Server trust and client credentials are configured independently. API callers do not supply certificate paths or passwords.

IP-address targets remain outside the current scope.

## Target

The report records:

- The requested hostname and port.
- The IP address used for the connection, when available.
- The UTC time of the diagnostic attempt.

The requested hostname is used for server identity validation.

## Check Outcomes

Each check has one of three outcomes:

- **Passed:** The check completed successfully.
- **Failed:** The check ran and detected a failure.
- **NotEvaluated:** The check was not reached or attempted.

| Check                  | Passed                                                   | Failed                                                 | NotEvaluated                           |
|------------------------|----------------------------------------------------------|--------------------------------------------------------|----------------------------------------|
| DNS resolution         | At least one address was resolved                        | Resolution failed                                      | Resolution was not attempted           |
| TCP connection         | A connection was established                             | The connection attempt failed                          | No connection was attempted            |
| TLS authentication     | The client-side TLS authentication operation completed under the configured policy     | Authentication failed, including certificate rejection | TCP connectivity was unavailable       |
| Certificate validation | The server certificate was accepted under the configured policy | Validation detected one or more errors                 | Certificate validation was not reached |

Certificate validation occurs during TLS authentication. If the server certificate is rejected, both checks can be Failed.

A failed check does not erase evidence already collected.

## Client Authentication Evidence

`ConfiguredClientCertificate` contains metadata from the configured PFX after successful loading and the private-key check. It is null when no client credential is configured. A configured credential that cannot load or lacks a private key causes an exception; it is not represented by a null summary in a returned report.

The summary is captured before networking and retained in every returned report, including DNS, TCP and TLS failure reports. It describes a local credential available for TLS selection. Its presence does not establish that the certificate was selected, sent or accepted remotely.

The summary includes subject, issuer, validity dates, SHA-256 fingerprint and DNS/IP SAN entries. It excludes file paths, passwords and private-key material. The validity dates are metadata; the summary does not assert that the client certificate is valid or trusted by the server.

Successful client-side TLS authentication does not establish that the server accepted the client certificate. Depending on the negotiated protocol and platform, server rejection may become observable only during subsequent communication. CertHub currently ends its inspection after the authentication operation.

Consequently, `TlsAuthentication: Passed` must not be interpreted as confirmed mutual authentication or application access. `CertificateValidation` describes the server certificate, independently of the server’s decision about the client.

Integration tests use server-side observations to verify presentation, acceptance and rejection of client certificates. Those observations are test evidence and are unavailable to the production probe.

Unreadable PFX files, incorrect passwords and credentials without a private key are local configuration failures. They propagate as exceptions rather than becoming target diagnostic findings.

## Evidence

The report contains the following information when available:

| Section            | Evidence                                                                                                                                                                                  |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Connection         | Connected IP, TCP-stage duration, negotiated TLS version and cipher suite. TCP-stage duration includes possible earlier failed address attempts and is currently recorded on TCP success. |
| Server certificate | Subject, issuer, validity dates, SHA-256 fingerprint, DNS SAN names and IP SAN addresses.                                                                                                                                  |
| Configured client certificate | Subject, issuer, validity dates, SHA-256 fingerprint and DNS/IP SAN entries from the successfully loaded client credential; null when none is configured. |
| Certificate chain  | Platform-built server chain in leaf-to-root order, with a certificate summary and status codes per element, plus overall chain status codes. Human-readable details remain in findings.                                                                                          |
| Findings           | Stable finding code, readable explanation and supporting details                                                                                                                          |
| Trust context      | Trust mode, configuration identifier and certificate evaluation time, configured custom-root fingerprints                                                                                 |

Unavailable information is omitted or represented as absent. It must not be interpreted as a successful check.

Certificate metadata may be partial. The built chain is not claimed to be an exact list of certificates sent by the
server.

### Subject Alternative Names

`CertificateSummary.DnsNames` and `CertificateSummary.IpAddresses` contain DNS-name and IP-address entries from the certificate's SAN extension. Both the server and configured client summaries use these fields.

Each collection is initialized and empty when that entry type is absent, including when the certificate has no SAN extension. A missing certificate summary remains null; an empty SAN collection does not indicate that the certificate itself is missing.

DNS entries are recorded as returned by the platform SAN parser without application-level matching, deduplication or lowercasing. IP entries are formatted using `IPAddress.ToString()`, including IPv4 and IPv6 addresses. Entries retain their order within each type; these separate arrays do not represent interleaving between DNS and IP entries in the extension.

Only DNS and IP SAN types are represented in this milestone. An empty pair of arrays does not establish that the certificate has no other SAN types, such as URI or email entries. The subject CN is not used to populate DNS SAN evidence.

SAN extraction describes certificate contents and does not change acceptance. Platform validation still determines hostname matching, trust and usage. DNS SAN evidence remains available when hostname validation rejects the server certificate. IP SAN evidence does not expand the API's hostname-only target contract.

### Server Certificate Chain

`TlsDiagnosticReport.ServerCertificateChain` is an immutable collection of `CertificateChainElement` values in platform-built leaf-to-root order. Each element holds a `CertificateSummary` and an immutable `StatusCodes` collection. An incomplete chain can terminate before reaching a root.

`TlsDiagnosticReport.ServerChainStatusCodes` contains the overall platform chain statuses. Both overall and per-element values are recorded as strings from `X509ChainStatusFlags`; explanatory platform messages remain in `CERT_CHAIN_INVALID` findings. The status sets can vary across platforms.

The probe copies the certificate summaries and statuses during the server validation callback, before callback-owned objects become unavailable. No live platform certificate or chain objects are retained in the domain report. Capturing this evidence does not alter validation or permit an invalid certificate.

The chain reflects the platform's construction under the configured trust policy. It can include locally available certificates or configured custom roots; it is not an exact list of certificates sent by the server. Automatic issuer-certificate downloads remain disabled.

Evidence is retained after certificate rejection and later TLS failure when the callback supplied it. For an expired server leaf under a valid trusted root, `NotTimeValid` can appear on the leaf and in the overall statuses while the root's statuses are empty.

Both report collections are initialized to empty when no chain evidence was captured, including DNS/TCP failures. Empty statuses are not a standalone success indicator: validation might not have run, and chain status does not represent hostname matching. Check outcomes and findings determine how to interpret the evidence.

### Planned Evidence

Following evidence is planned to be included in future implementations:

- ALPN

## Validation Policy

Certificate validation remains enforced.

The probe captures available certificate information and validation errors, then rejects certificates that fail the
configured policy. It does not accept invalid certificates merely to complete the handshake.

The policy checks:

- Server identity against the requested hostname.
- Certificate-chain trust.
- Certificate validity periods.
- Suitability for TLS server authentication.

Platform TLS and certificate facilities perform these checks. CertHub translates their results into diagnostic findings.

Revocation checking and automatic issuer-certificate downloads are disabled by the current implementation. These
limitations are documented here; the report does not yet contain explicit policy fields for them.

## Trust Context

The probe supports two trust modes:

- **System:** Use the operating system's trust anchors.
- **CustomRoots:** Use explicitly configured root certificates as trust anchors.

Each report records the mode and a configuration identifier, such as `system` or `lab-root-ca`. Custom-root fingerprints
identify the roots used.

System trust may differ between machines. The identifier alone does not guarantee identical trust configuration.

Trust configuration is controlled by the application. API callers do not upload CA certificates in the first version.

## Findings

A report can contain multiple findings. For example, a certificate may be expired and fail hostname validation.

Initial finding categories include:

| Stage       | Codes                                                                |
|-------------|----------------------------------------------------------------------|
| DNS         | `DNS_RESOLUTION_FAILED`, `DNS_TIMEOUT`                               |
| TCP         | `TCP_CONNECTION_FAILED`, `TCP_TIMEOUT`                               |
| TLS         | `TLS_AUTHENTICATION_FAILED`, `TLS_CONNECTION_FAILED`, `TLS_TIMEOUT`  |
| Certificate | `CERT_NOT_PRESENTED`, `CERT_HOSTNAME_MISMATCH`, `CERT_CHAIN_INVALID`, `CERT_EXPIRED`, `CERT_NOT_YET_VALID` |

Incomplete chains and invalid usage currently appear as platform details under CERT_CHAIN_INVALID, rather than dedicated
codes.

Chain-status codes are retained in the structured overall and per-element collections, with explanatory details in `CERT_CHAIN_INVALID` messages. Unexpected implementation errors propagate.

A timeout does not prove that the server is down. Findings describe what was observed without asserting an unsupported
cause.

## Timeout and Cancellation

The diagnostic attempt has a bounded timeout.

The timeout budget starts after client credential loading and is shared across the network diagnostic stages. Synchronous certificate-file loading is not cancellable through this timeout.

When the probe's timeout expires, the report identifies the stage where it occurred and preserves existing evidence.

Caller cancellation propagates to the caller and is not reported as a target timeout.

## Example Outcomes

These examples describe expected behaviour with validation enforced.

| Scenario                      | DNS    | TCP          | TLS authentication | Certificate validation |
|-------------------------------|--------|--------------|--------------------|------------------------|
| Valid server certificate      | Passed | Passed       | Passed             | Passed                 |
| Untrusted certificate chain   | Passed | Passed       | Failed             | Failed                 |
| Hostname mismatch             | Passed | Passed       | Failed             | Failed                 |
| Expired certificate           | Passed | Passed       | Failed             | Failed                 |
| TLS failure before validation | Passed | Passed       | Failed             | NotEvaluated           |
| TCP connection refused        | Passed | Failed       | NotEvaluated       | NotEvaluated           |
| DNS resolution failure        | Failed | NotEvaluated | NotEvaluated       | NotEvaluated           |

Certificate metadata can remain available when certificate validation fails. Negotiated connection information is
recorded only when the probe can establish it.

## Implemented Types

The following types are implemented under `CertHub.Domain/Diagnostics/`:

- `CheckOutcome` — Passed, Failed or NotEvaluated.
- `DiagnosticFinding` — A finding code, and a message with explanation and supporting details.
- `CertificateSummary` — Certificate metadata, including immutable DNS/IP SAN collections, reused for the server certificate and configured client credential.
- `CertificateChainElement` — A certificate summary and immutable platform status-code collection for one built-chain element.
- `TlsDiagnosticReport` — Target, check outcomes, server and configured client certificate summaries, structured server chain evidence, connection evidence, findings and trust context.
- `ConnectionSummary`
- `TrustContext`
- `TrustMode`
