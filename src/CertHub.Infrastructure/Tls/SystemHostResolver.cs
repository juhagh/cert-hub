using System.Net;

namespace CertHub.Infrastructure.Tls;

public sealed class SystemHostResolver : IHostResolver
{
    public Task<IPAddress[]> ResolveAsync(string hostname, CancellationToken ct = default)
    {
        return Dns.GetHostAddressesAsync(hostname, ct);
    }
}