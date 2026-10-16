using System.Collections.Immutable;

namespace CertHub.Domain.Diagnostics;

public sealed record TlsDiagnosticReport(
    string Hostname,
    int Port,
    DateTimeOffset AttemptedAt,
    CheckOutcome DnsResolution,
    CheckOutcome TcpConnection,
    CheckOutcome TlsAuthentication,
    CheckOutcome CertificateValidation,
    ConnectionSummary Connection,
    CertificateSummary? Certificate,
    TrustContext TrustContext,
    ImmutableArray<DiagnosticFinding> Findings);