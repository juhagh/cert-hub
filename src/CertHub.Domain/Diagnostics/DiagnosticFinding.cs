namespace CertHub.Domain.Diagnostics;

public sealed record DiagnosticFinding(
    string Code,
    string Message);