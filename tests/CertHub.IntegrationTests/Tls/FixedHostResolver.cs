using System.Net;
using CertHub.Infrastructure.Tls;

namespace CertHub.IntegrationTests.Tls;

public sealed class FixedHostResolver : IHostResolver
{
    private readonly IPAddress[] _ipAddresses;

    public FixedHostResolver(IPAddress[] ipAddresses)
    {
        _ipAddresses = ipAddresses;
    }
    
    public Task<IPAddress[]> ResolveAsync(string hostname, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        return Task.FromResult(_ipAddresses);
    }
}