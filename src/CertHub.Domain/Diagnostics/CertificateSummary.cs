namespace CertHub.Domain.Diagnostics;

public sealed record CertificateSummary(
    string Subject,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string Sha256Fingerprint);