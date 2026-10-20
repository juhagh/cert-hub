using CertHub.Application.Abstractions;
using CertHub.Application.Diagnostics;
using CertHub.Domain.Diagnostics;

namespace CertHub.IntegrationTests.Diagnostics;

public sealed class StubTlsProbe : ITlsProbe
{
    public int CallCount { get; private set; } 
    public TlsDiagnosticReport? ReportToReturn { get; set; }
    public TlsProbeRequest? LastRequest { get; private set; }
    
    public Task<TlsDiagnosticReport> ProbeAsync(TlsProbeRequest request, CancellationToken ct = default)
    {
        CallCount++;
        LastRequest = request;

        if (ReportToReturn is null)
        {
            throw new InvalidOperationException("ReportToReturn has not been configured.");
        }

        return Task.FromResult(ReportToReturn);
    }
}