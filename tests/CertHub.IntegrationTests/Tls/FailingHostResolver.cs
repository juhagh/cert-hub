using System.Net;
using System.Net.Sockets;
using CertHub.Infrastructure.Tls;

namespace CertHub.IntegrationTests.Tls;

public sealed class FailingHostResolver : IHostResolver
{
    public Task<IPAddress[]> ResolveAsync(string hostname, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var exception = new SocketException((int)SocketError.HostNotFound, "This is a test exception.");
        return Task.FromException<IPAddress[]>(exception);
    }
}