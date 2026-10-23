using System.Net;
using CertHub.Infrastructure.Tls;

namespace CertHub.IntegrationTests.Tls;

public sealed class EmptyHostResolver : IHostResolver
{
    public Task<IPAddress[]> ResolveAsync(string hostname, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        return Task.FromResult(Array.Empty<IPAddress>());
    }
}