using System.Net;
using System.Net.Sockets;

namespace CertHub.IntegrationTests.Tls;

public sealed class StallingTlsTestServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _shutdownCts = new CancellationTokenSource();
    private readonly Task _serverTask;
    
    public int Port { get; }
    
    private readonly TaskCompletionSource _clientHelloReceived = 
        new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

    public Task ClientHelloReceived => _clientHelloReceived.Task;

    public StallingTlsTestServer()
    {
        _listener = new TcpListener(localaddr: IPAddress.Loopback, port: 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _serverTask = ServeConnectionAsync(_shutdownCts.Token);
    }
    
    public async ValueTask DisposeAsync()
    {
        try
        {
            _shutdownCts.Cancel();
            _listener.Stop();
            await _serverTask;
        }
        catch (OperationCanceledException) when (_shutdownCts.IsCancellationRequested)
        {
            // Cancellation is expected  because disposal requests for cancel.
        }
        finally
        {
            _shutdownCts.Dispose();
        }
    }
    
    private async Task ServeConnectionAsync(CancellationToken ct)
    {
        using var client = await _listener.AcceptTcpClientAsync(ct);

        using var stream = client.GetStream();

        byte[] receiveBuffer = new byte[1];

        var bytesRead = await stream.ReadAsync(receiveBuffer, ct);

        if (bytesRead == 0)
        {
            throw new IOException("Client closed the connection before sending TLS traffic.");
        }

        _clientHelloReceived.TrySetResult();
        await Task.Delay(Timeout.InfiniteTimeSpan, ct);
    } 
}