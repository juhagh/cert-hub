using CertHub.Application.Diagnostics;
using CertHub.Domain.Diagnostics;
using CertHub.Infrastructure.Tls;
using Microsoft.Extensions.Options;

namespace CertHub.IntegrationTests.Tls;

public sealed class TlsProbeTests
{
    [Fact]
    public async Task ProbeAsync_WithUntrustedServerCertificate_ReturnsValidationFailure()
    {
        var timeProvider = TimeProvider.System;
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromSeconds(5),
            TrustMode = TrustMode.System
        };

        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options);

        await using TlsTestServer testServer = new TlsTestServer();
        var request = new TlsProbeRequest("localhost", testServer.Port);

        var result = await sut.ProbeAsync(request);
        
        Assert.Equal(CheckOutcome.Passed, result.DnsResolution);
        Assert.Equal(CheckOutcome.Passed, result.TcpConnection);
        Assert.Equal(CheckOutcome.Failed, result.TlsAuthentication);
        Assert.Equal(CheckOutcome.Failed, result.CertificateValidation);
        Assert.NotNull(result.Certificate);
        Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Sha256Fingerprint));
        Assert.False(string.IsNullOrWhiteSpace(result.Connection.RemoteIpAddress));
        Assert.Contains(result.Findings, f => f.Code == "CERT_CHAIN_INVALID");
        Assert.Contains(result.Findings, f => f.Code == "TLS_AUTHENTICATION_FAILED");
        Assert.DoesNotContain(result.Findings, f => f.Code == "CERT_HOSTNAME_MISMATCH");
    }

    [Fact]
    public async Task ProbeAsync_WhenAlreadyCancelled_ThrowsOperationCanceledException()
    {
        var timeProvider = TimeProvider.System;
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromSeconds(5),
            TrustMode = TrustMode.System
        };

        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options);
        var request = new TlsProbeRequest("localhost", 8443);
        
        using var cts = new CancellationTokenSource();

        cts.Cancel();
        
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sut.ProbeAsync(request, cts.Token));
    }

    [Fact]
    public async Task ProbeAsync_WhenCancelledDuringTlsAuthentication_ThrowsOperationCanceledException()
    {
        var timeProvider = TimeProvider.System;
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromSeconds(30),
            TrustMode = TrustMode.System
        };

        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options);

        await using StallingTlsTestServer testServer = new StallingTlsTestServer();
        var request = new TlsProbeRequest("localhost", testServer.Port);
        using var cts = new CancellationTokenSource();
        
        var probeTask = sut.ProbeAsync(request, cts.Token);
        await testServer.ClientHelloReceived.WaitAsync(TimeSpan.FromSeconds(5));
        
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => probeTask.WaitAsync(TimeSpan.FromSeconds(5)));
    }
}