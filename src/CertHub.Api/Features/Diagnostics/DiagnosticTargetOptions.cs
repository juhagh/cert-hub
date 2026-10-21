namespace CertHub.Api.Features.Diagnostics;

public sealed class DiagnosticTargetOptions
{
    public AllowedDiagnosticTarget[] AllowedTargets { get; set; } = [];
}