using System.Net;
using CertHub.Infrastructure.Tls;

namespace CertHub.IntegrationTests.Tls;

public sealed class StallingHostResolver : IHostResolver
{
    private readonly TaskCompletionSource _resolutionStarted = 
        new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    
    public Task ResolutionStarted => _resolutionStarted.Task;
    
    public async Task<IPAddress[]> ResolveAsync(string hostname, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        
        _resolutionStarted.TrySetResult();

        await Task.Delay(Timeout.InfiniteTimeSpan, ct);
        
        return Array.Empty<IPAddress>();
    }
}