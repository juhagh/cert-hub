# Diagnostic Report Design

## Purpose

CertHub reports the outcome of a TLS connection attempt and the evidence available to explain it.

A failed connection is an expected diagnostic result. The report distinguishes observed failures from possible causes and preserves evidence gathered before failure.

## Initial Scope

The first version checks a DNS hostname and port, such as `localhost:8443`.

It performs server TLS authentication without sending an HTTP request or other application data. Client certificates and IP-address targets are outside the initial scope.

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

| Check | Passed | Failed | NotEvaluated |
|---|---|---|---|
| DNS resolution | At least one address was resolved | Resolution failed | Resolution was not attempted |
| TCP connection | A connection was established | The connection attempt failed | No connection was attempted |
| TLS authentication | Authentication completed under the configured policy | Authentication failed, including certificate rejection | TCP connectivity was unavailable |
| Certificate validation | The certificate was accepted under the configured policy | Validation detected one or more errors | Certificate validation was not reached |

Certificate validation occurs during TLS authentication. If a certificate is rejected, both checks can be Failed.

A failed check does not erase evidence already collected.

## Evidence

The report contains the following information when available:

| Section | Evidence |
|---|---|
| Connection | Connected IP address, TCP connection duration, negotiated TLS version, cipher suite and ALPN protocol |
| Server certificate | Subject, issuer, Subject Alternative Names, validity dates and SHA-256 fingerprint |
| Certificate chain | Available built-chain elements and their validation errors |
| Findings | Stable finding code, readable explanation and supporting details |
| Trust context | Trust mode, configuration identifier and certificate evaluation time |

Unavailable information is omitted or represented as absent. It must not be interpreted as a successful check.

Certificate metadata may be partial. The built chain is not claimed to be an exact list of certificates sent by the server.

## Validation Policy

Certificate validation remains enforced.

The probe captures available certificate information and validation errors, then rejects certificates that fail the configured policy. It does not accept invalid certificates merely to complete the handshake.

The policy checks:

- Server identity against the requested hostname.
- Certificate-chain trust.
- Certificate validity periods.
- Suitability for TLS server authentication.

Platform TLS and certificate facilities perform these checks. CertHub translates their results into diagnostic findings.

Revocation checking and automatic downloads of missing issuer certificates are disabled for the initial milestone. These limitations are stated in the report.

## Trust Context

The probe supports two trust modes:

- **System:** Use the operating system's trust anchors.
- **CustomRoots:** Use explicitly configured root certificates as trust anchors.

Each report records the mode and a configuration identifier, such as `system` or `lab-root-ca`. Custom-root fingerprints identify the roots used.

System trust may differ between machines. The identifier alone does not guarantee identical trust configuration.

Trust configuration is controlled by the application. API callers do not upload CA certificates in the first version.

## Findings

A report can contain multiple findings. For example, a certificate may be expired and fail hostname validation.

Initial finding categories include:

- DNS resolution failure.
- TCP connection refusal, timeout or other connection error.
- TLS authentication failure.
- Certificate unavailable.
- Hostname mismatch.
- Untrusted or incomplete certificate chain.
- Expired or not-yet-valid certificate.
- Invalid certificate usage.
- Other validation errors.

Unrecognised errors are retained as general findings with available supporting details.

A timeout does not prove that the server is down. Findings describe what was observed without asserting an unsupported cause.

## Timeout and Cancellation

The diagnostic attempt has a bounded timeout.

When the probe's timeout expires, the report identifies the stage where it occurred and preserves existing evidence.

Caller cancellation propagates to the caller and is not reported as a target timeout.

## Example Outcomes

These examples describe expected behaviour with validation enforced.

| Scenario | DNS | TCP | TLS authentication | Certificate validation |
|---|---|---|---|---|
| Valid server certificate | Passed | Passed | Passed | Passed |
| Untrusted certificate chain | Passed | Passed | Failed | Failed |
| Hostname mismatch | Passed | Passed | Failed | Failed |
| Expired certificate | Passed | Passed | Failed | Failed |
| TLS failure before validation | Passed | Passed | Failed | NotEvaluated |
| TCP connection refused | Passed | Failed | NotEvaluated | NotEvaluated |
| DNS resolution failure | Failed | NotEvaluated | NotEvaluated | NotEvaluated |

Certificate metadata can remain available when certificate validation fails. Negotiated connection information is recorded only when the probe can establish it.

## Initial Types

The design will begin with these types under `CertHub.Domain/Diagnostics/`:

- `CheckOutcome` — Passed, Failed or NotEvaluated.
- `DiagnosticFinding` — A finding code, explanation and supporting details.
- `CertificateSummary` — Available server-certificate metadata.
- `TlsDiagnosticReport` — Target, check outcomes, evidence, findings and trust context.

Their exact properties will be defined as the first use case is implemented.