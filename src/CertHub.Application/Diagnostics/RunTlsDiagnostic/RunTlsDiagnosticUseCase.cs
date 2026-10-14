using CertHub.Application.Abstractions;
using CertHub.Domain.Diagnostics;

namespace CertHub.Application.Diagnostics.RunTlsDiagnostic;

public sealed class RunTlsDiagnosticUseCase
{
    private readonly ITlsProbe _probe;
    
    public RunTlsDiagnosticUseCase(ITlsProbe probe)
    {
        _probe = probe;
    }

    public async Task<TlsDiagnosticReport> ExecuteAsync(TlsProbeRequest request, CancellationToken ct)
    {
        return await _probe.ProbeAsync(request, ct);
    }
}