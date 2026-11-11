using System.Collections.Immutable;

namespace CertHub.Domain.Diagnostics;

public sealed record CertificateSummary(
    string Subject,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string Sha256Fingerprint,
    ImmutableArray<string> DnsNames,
    ImmutableArray<string> IpAddresses);