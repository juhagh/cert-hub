using CertHub.Application.Diagnostics;
using CertHub.Domain.Diagnostics;

namespace CertHub.Application.Abstractions;

public interface ITlsProbe
{
    Task<TlsDiagnosticReport> ProbeAsync(TlsProbeRequest request, CancellationToken ct = default);
}