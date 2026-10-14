using System.Collections.Immutable;

namespace CertHub.Domain.Diagnostics;

public sealed record TrustContext(
    TrustMode Mode,
    string ConfigurationId,
    ImmutableArray<string> RootSha256Fingerprints,
    DateTimeOffset EvaluationTime);