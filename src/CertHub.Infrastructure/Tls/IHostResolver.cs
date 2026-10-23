using System.Net;

namespace CertHub.Infrastructure.Tls;

public interface IHostResolver
{
    Task<IPAddress[]> ResolveAsync(string hostname, CancellationToken ct = default);
}