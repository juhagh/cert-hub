using System.Collections.Immutable;

namespace CertHub.Domain.Diagnostics;

public sealed record CertificateChainElement(
    CertificateSummary Certificate,
    ImmutableArray<string> StatusCodes);