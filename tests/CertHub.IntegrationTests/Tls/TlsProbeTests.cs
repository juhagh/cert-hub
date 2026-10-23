using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
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
            TrustMode = TrustMode.System,
        };

        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());

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
        var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());
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
        var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());

        await using StallingTlsTestServer testServer = new StallingTlsTestServer();
        var request = new TlsProbeRequest("localhost", testServer.Port);
        using var cts = new CancellationTokenSource();
        
        var probeTask = sut.ProbeAsync(request, cts.Token);
        await testServer.ClientHelloReceived.WaitAsync(TimeSpan.FromSeconds(5));
        
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => probeTask.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task ProbeAsync_WhenTlsAuthenticationTimesOut_ReturnsTimeoutReport()
    {
        var timeProvider = TimeProvider.System;
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromSeconds(2),
            TrustMode = TrustMode.System
        };

        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());

        await using StallingTlsTestServer testServer = new StallingTlsTestServer();
        var request = new TlsProbeRequest("localhost", testServer.Port);
        
        var probeTask = sut.ProbeAsync(request);
        
        await testServer.ClientHelloReceived.WaitAsync(TimeSpan.FromSeconds(5));
        
        var result = await probeTask.WaitAsync(TimeSpan.FromSeconds(5));
        
        
        Assert.Equal(CheckOutcome.Passed, result.DnsResolution);
        Assert.Equal(CheckOutcome.Passed, result.TcpConnection);
        Assert.Equal(CheckOutcome.Failed, result.TlsAuthentication);
        Assert.Equal(CheckOutcome.NotEvaluated, result.CertificateValidation);
        Assert.False(string.IsNullOrWhiteSpace(result.Connection.RemoteIpAddress));
        Assert.Null(result.Certificate);
        Assert.Null(result.Connection.TlsProtocol);
        Assert.Null(result.Connection.CipherSuite);
        Assert.Contains(result.Findings, f => f.Code == "TLS_TIMEOUT");
    }

    [Fact]
    public async Task ProbeAsync_WithConfiguredCustomRoot_ReturnsSuccessfulAuthentication()
    { 
        using var issuer = TlsTestServer.CreateCertificateAuthority();

        var certificateFile = Path.GetTempFileName();

        try
        {
            string publicCert = issuer.ExportCertificatePem();
            File.WriteAllText(certificateFile, publicCert);
            
            var timeProvider = TimeProvider.System;
            var localSettings = new TlsProbeOptions
            {
                Timeout = TimeSpan.FromSeconds(5),
                TrustMode = TrustMode.CustomRoots,
                TrustConfigurationId = "test-root-ca",
                RootCertificatePaths = [certificateFile]
            };

            var options = Options.Create(localSettings);
            var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());

            await using TlsTestServer testServer = new TlsTestServer(issuer);
            var request = new TlsProbeRequest("localhost", testServer.Port);
            
            var result = await sut.ProbeAsync(request);
            
            
            Assert.Equal(CheckOutcome.Passed, result.DnsResolution);
            Assert.Equal(CheckOutcome.Passed, result.TcpConnection);
            Assert.Equal(CheckOutcome.Passed, result.TlsAuthentication);
            Assert.Equal(CheckOutcome.Passed, result.CertificateValidation);
            
            Assert.NotNull(result.Connection);
            Assert.NotNull(result.Certificate);
            Assert.False(string.IsNullOrWhiteSpace(result.Connection.RemoteIpAddress));
            Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Issuer));
            Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Subject));
            Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Sha256Fingerprint));
            
            Assert.NotEqual(default, result.Certificate.NotAfter);
            Assert.NotEqual(default, result.Certificate.NotBefore);

            Assert.False(string.IsNullOrWhiteSpace(result.Connection.TlsProtocol));
            Assert.False(string.IsNullOrWhiteSpace(result.Connection.CipherSuite));

            Assert.True(result.Certificate.NotAfter > result.Certificate.NotBefore);
            Assert.Equal(TrustMode.CustomRoots, result.TrustContext.Mode);
            Assert.Equal(localSettings.TrustConfigurationId, result.TrustContext.ConfigurationId);
            Assert.Contains(issuer.GetCertHashString(HashAlgorithmName.SHA256), result.TrustContext.RootSha256Fingerprints);
            Assert.DoesNotContain(result.Findings, f => f.Code.StartsWith("CERT_"));
            Assert.DoesNotContain(result.Findings, f => f.Code.StartsWith("TLS_"));
        }
        finally
        {
            File.Delete(certificateFile);
        }
    }
    
    [Fact]
    public async Task ProbeAsync_WithUnrelatedCustomRoot_ReturnsValidationFailure()
    { 
        using var issuer = TlsTestServer.CreateCertificateAuthority();
        using var unrelatedRoot = TlsTestServer.CreateCertificateAuthority();

        var certificateFile = Path.GetTempFileName();

        try
        {
            string unrelatedCert = unrelatedRoot.ExportCertificatePem();
            File.WriteAllText(certificateFile, unrelatedCert);
            
            var timeProvider = TimeProvider.System;
            var localSettings = new TlsProbeOptions
            {
                Timeout = TimeSpan.FromSeconds(5),
                TrustMode = TrustMode.CustomRoots,
                TrustConfigurationId = "unrelated-test-root",
                RootCertificatePaths = [certificateFile]
            };

            var options = Options.Create(localSettings);
            var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());

            await using TlsTestServer testServer = new TlsTestServer(issuer);
            var request = new TlsProbeRequest("localhost", testServer.Port);
            
            var result = await sut.ProbeAsync(request);
            
            Assert.Equal(CheckOutcome.Passed, result.DnsResolution);
            Assert.Equal(CheckOutcome.Passed, result.TcpConnection);
            Assert.Equal(CheckOutcome.Failed, result.TlsAuthentication);
            Assert.Equal(CheckOutcome.Failed, result.CertificateValidation);
            
            Assert.NotNull(result.Connection);
            Assert.NotNull(result.Certificate);
            Assert.False(string.IsNullOrWhiteSpace(result.Connection.RemoteIpAddress));
            Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Issuer));
            Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Subject));
            Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Sha256Fingerprint));
            
            Assert.NotEqual(default, result.Certificate.NotAfter);
            Assert.NotEqual(default, result.Certificate.NotBefore);

            Assert.Null(result.Connection.TlsProtocol);
            Assert.Null(result.Connection.CipherSuite);

            Assert.True(result.Certificate.NotAfter > result.Certificate.NotBefore);
            Assert.Equal(TrustMode.CustomRoots, result.TrustContext.Mode);
            Assert.Equal(localSettings.TrustConfigurationId, result.TrustContext.ConfigurationId);
            Assert.Contains(unrelatedRoot.GetCertHashString(HashAlgorithmName.SHA256), result.TrustContext.RootSha256Fingerprints);
            Assert.DoesNotContain(issuer.GetCertHashString(HashAlgorithmName.SHA256), result.TrustContext.RootSha256Fingerprints);
            
            Assert.DoesNotContain(result.Findings, f => f.Code == "CERT_HOSTNAME_MISMATCH");
            Assert.Contains(result.Findings, f => f.Code == "CERT_CHAIN_INVALID");
        }
        finally
        {
            File.Delete(certificateFile);
        }
    }

    [Fact]
    public async Task ProbeAsync_WithTrustedCertificateForDifferentHostname_ReturnsNameMismatch()
    {
        using var issuer = TlsTestServer.CreateCertificateAuthority();

        var certificateFile = Path.GetTempFileName();

        try
        {
            string publicCert = issuer.ExportCertificatePem();
            File.WriteAllText(certificateFile, publicCert);
            
            var timeProvider = TimeProvider.System;
            var localSettings = new TlsProbeOptions
            {
                Timeout = TimeSpan.FromSeconds(5),
                TrustMode = TrustMode.CustomRoots,
                TrustConfigurationId = "test-root-ca",
                RootCertificatePaths = [certificateFile]
            };

            var options = Options.Create(localSettings);
            var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());

            await using TlsTestServer testServer = new TlsTestServer(issuer, "wrong-host.example");
            var request = new TlsProbeRequest("localhost", testServer.Port);
            
            var result = await sut.ProbeAsync(request);
            
            
            Assert.Equal(CheckOutcome.Passed, result.DnsResolution);
            Assert.Equal(CheckOutcome.Passed, result.TcpConnection);
            Assert.Equal(CheckOutcome.Failed, result.TlsAuthentication);
            Assert.Equal(CheckOutcome.Failed, result.CertificateValidation);
            
            Assert.NotNull(result.Connection);
            Assert.NotNull(result.Certificate);
            Assert.False(string.IsNullOrWhiteSpace(result.Connection.RemoteIpAddress));
            Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Issuer));
            Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Subject));
            Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Sha256Fingerprint));
            
            Assert.NotEqual(default, result.Certificate.NotAfter);
            Assert.NotEqual(default, result.Certificate.NotBefore);

            Assert.Null(result.Connection.TlsProtocol);
            Assert.Null(result.Connection.CipherSuite);

            Assert.True(result.Certificate.NotAfter > result.Certificate.NotBefore);
            Assert.Equal(TrustMode.CustomRoots, result.TrustContext.Mode);
            Assert.Equal(localSettings.TrustConfigurationId, result.TrustContext.ConfigurationId);
            Assert.Contains(issuer.GetCertHashString(HashAlgorithmName.SHA256), result.TrustContext.RootSha256Fingerprints);
            
            Assert.Contains(result.Findings, f => f.Code == "CERT_HOSTNAME_MISMATCH");
            Assert.Contains(result.Findings, f => f.Code == "TLS_AUTHENTICATION_FAILED");
            Assert.DoesNotContain(result.Findings, f => f.Code == "CERT_CHAIN_INVALID");
        }
        finally
        {
            File.Delete(certificateFile);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-1000)]
    [InlineData(60001)]
    public async Task ProbeAsync_WithInvalidTimeout_ThrowsInvalidOperationException(int timeoutMilliseconds)
    {
        var timeProvider = TimeProvider.System;
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromMilliseconds(timeoutMilliseconds),
            TrustMode = TrustMode.System
        };

        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());
        
        var request = new TlsProbeRequest("localhost", 8443);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => sut.ProbeAsync(request));

        Assert.Contains("Timeout", exception.Message);
    }

    [Fact]
    public async Task ProbeAsync_WithUnsupportedTrustMode_ThrowsInvalidOperationException()
    {
        var timeProvider = TimeProvider.System;
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromMilliseconds(10000),
            TrustMode = (TrustMode)999
        };

        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());
        
        var request = new TlsProbeRequest("localhost", 8443);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => sut.ProbeAsync(request));

        Assert.Contains("Trust mode", exception.Message);
    }
    
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("system")]
    public async Task ProbeAsync_WithInvalidCustomTrustConfigurationId_ThrowsInvalidOperationException(string? configurationId)
    {
        var timeProvider = TimeProvider.System;
        string[] certificatePath = ["fakepath"];
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromMilliseconds(10000),
            TrustMode = TrustMode.CustomRoots,
            RootCertificatePaths = certificatePath,
            TrustConfigurationId = configurationId!
        };
        
        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());
        
        var request = new TlsProbeRequest("localhost", 8443);
    
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => sut.ProbeAsync(request));
    
        Assert.Contains("TrustConfigurationId", exception.Message);
    }
    
    [Fact]
    public async Task ProbeAsync_WithNullRootCertificatePaths_ThrowsInvalidOperationException()
    {
        var timeProvider = TimeProvider.System;
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromMilliseconds(10000),
            TrustMode = TrustMode.CustomRoots,
            RootCertificatePaths = null!,
            TrustConfigurationId = "test-root-ca"
        };
        
        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());
        
        var request = new TlsProbeRequest("localhost", 8443);
    
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => sut.ProbeAsync(request));
    
        Assert.Contains("at least one certificate path", exception.Message);
    }
    
    [Fact]
    public async Task ProbeAsync_WithEmptyRootCertificatePaths_ThrowsInvalidOperationException()
    {
        var timeProvider = TimeProvider.System;
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromMilliseconds(10000),
            TrustMode = TrustMode.CustomRoots,
            RootCertificatePaths = [],
            TrustConfigurationId = "test-root-ca"
        };
        
        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());
        
        var request = new TlsProbeRequest("localhost", 8443);
    
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => sut.ProbeAsync(request));
    
        Assert.Contains("at least one certificate path", exception.Message);
    }
    
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public async Task ProbeAsync_WithInvalidRootCertificatePathEntry_ThrowsInvalidOperationException(string? certificatePathEntry)
    {
        var timeProvider = TimeProvider.System;
        string[] certificatePath = [certificatePathEntry!];
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromMilliseconds(10000),
            TrustMode = TrustMode.CustomRoots,
            RootCertificatePaths = certificatePath,
            TrustConfigurationId = "test-root-ca"
        };
        
        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());
        
        var request = new TlsProbeRequest("localhost", 8443);
    
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => sut.ProbeAsync(request));
    
        Assert.Contains("certificate path cannot be empty", exception.Message);
    }

    [Fact]
    public async Task ProbeAsync_WithBlankRootPathAfterNonBlankEntry_ThrowsInvalidOperationException()
    {
        var timeProvider = TimeProvider.System;
        string[] certificatePath = ["validEntry", " "];
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromMilliseconds(10000),
            TrustMode = TrustMode.CustomRoots,
            RootCertificatePaths = certificatePath,
            TrustConfigurationId = "test-root-ca"
        };
        
        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());
        
        var request = new TlsProbeRequest("localhost", 8443);
    
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => sut.ProbeAsync(request));
    
        Assert.Contains("certificate path cannot be empty", exception.Message);
    }

    [Fact]
    public async Task ProbeAsync_WhenConnectionIsRefused_ReturnsTcpFailureReport()
    {
        var timeProvider = TimeProvider.System;
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromSeconds(5),
            TrustMode = TrustMode.System,
        };
        
        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());
        
        var request = new TlsProbeRequest("127.0.0.1", GetUnusedLoopBackPort());

        var result = await sut.ProbeAsync(request);

        Assert.Equal(CheckOutcome.Passed, result.DnsResolution);
        Assert.Equal(CheckOutcome.Failed, result.TcpConnection);
        Assert.Equal(CheckOutcome.NotEvaluated, result.TlsAuthentication);
        Assert.Equal(CheckOutcome.NotEvaluated, result.CertificateValidation);
        Assert.Null(result.Certificate);
        Assert.Null(result.Connection.TlsProtocol);
        Assert.Null(result.Connection.CipherSuite);
        Assert.Contains(result.Findings, f => f.Code == "TCP_CONNECTION_FAILED" && 
                                              f.Message.Contains(nameof(SocketError.ConnectionRefused)));
        Assert.DoesNotContain(result.Findings, f => f.Code == "TCP_TIMEOUT");
        Assert.DoesNotContain(result.Findings, f => f.Code == "TLS_AUTHENTICATION_FAILED");
    }

    [Fact]
    public async Task ProbeAsync_WhenHostnameCannotBeResolved_ReturnsDnsFailureReport()
    {
        var timeProvider = TimeProvider.System;
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromSeconds(5),
            TrustMode = TrustMode.System,
        };
        
        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options, new FailingHostResolver());
        
        var request = new TlsProbeRequest("does-not-exist.invalid", 443);

        var result = await sut.ProbeAsync(request);
        
        Assert.Equal(CheckOutcome.Failed, result.DnsResolution);
        Assert.Equal(CheckOutcome.NotEvaluated, result.TcpConnection);
        Assert.Equal(CheckOutcome.NotEvaluated, result.TlsAuthentication);
        Assert.Equal(CheckOutcome.NotEvaluated, result.CertificateValidation);
        Assert.Null(result.Certificate);
        Assert.Contains(result.Findings, f => f.Code == "DNS_RESOLUTION_FAILED");
    }

    [Fact]
    public async Task ProbeAsync_WhenResolverReturnsNoAddresses_ReturnsDnsFailureReport()
    {
        var timeProvider = TimeProvider.System;
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromSeconds(5),
            TrustMode = TrustMode.System,
        };
        
        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options, new EmptyHostResolver());
        
        var request = new TlsProbeRequest("localhost", 8443);

        var result = await sut.ProbeAsync(request);
        
        Assert.Equal(CheckOutcome.Failed, result.DnsResolution);
        Assert.Equal(CheckOutcome.NotEvaluated, result.TcpConnection);
        Assert.Equal(CheckOutcome.NotEvaluated, result.TlsAuthentication);
        Assert.Equal(CheckOutcome.NotEvaluated, result.CertificateValidation);
        Assert.Null(result.Certificate);
        Assert.Contains(result.Findings, f => f.Code == "DNS_RESOLUTION_FAILED");
    }

    [Fact]
    public async Task ProbeAsync_WhenDnsResolutionTimesOut_ReturnsTimeoutReport()
    {
        var timeProvider = TimeProvider.System;
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromSeconds(2),
            TrustMode = TrustMode.System,
        };

        var hostResolver = new StallingHostResolver();
        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options, hostResolver);
        
        var request = new TlsProbeRequest("localhost", 8443);

        var probeTask = sut.ProbeAsync(request);
        
        await hostResolver.ResolutionStarted.WaitAsync(TimeSpan.FromSeconds(5));

        var result = await probeTask.WaitAsync(TimeSpan.FromSeconds(5));
        
        Assert.Equal(CheckOutcome.Failed, result.DnsResolution);
        Assert.Equal(CheckOutcome.NotEvaluated, result.TcpConnection);
        Assert.Equal(CheckOutcome.NotEvaluated, result.TlsAuthentication);
        Assert.Equal(CheckOutcome.NotEvaluated, result.CertificateValidation);
        Assert.Null(result.Certificate);
        Assert.Contains(result.Findings, f => f.Code == "DNS_TIMEOUT");
        Assert.DoesNotContain(result.Findings, f => f.Code == "DNS_RESOLUTION_FAILED");
    }

    [Fact]
    public async Task ProbeAsync_WhenCancelledDuringDnsResolution_ThrowsOperationCanceledException()
    {
        var timeProvider = TimeProvider.System;
        var localSettings = new TlsProbeOptions
        {
            Timeout = TimeSpan.FromSeconds(30),
            TrustMode = TrustMode.System,
        };

        var hostResolver = new StallingHostResolver();
        var options = Options.Create(localSettings);
        var sut = new TlsProbe(timeProvider, options, hostResolver);
        
        var request = new TlsProbeRequest("localhost", 8443);

        using var cts = new CancellationTokenSource();
        
        var probeTask = sut.ProbeAsync(request, cts.Token);
        
        await hostResolver.ResolutionStarted.WaitAsync(TimeSpan.FromSeconds(5));

        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => probeTask.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task ProbeAsync_WhenFirstAddressFails_ConnectsToNextAddress()
    {
        using var issuer = TlsTestServer.CreateCertificateAuthority();

        var certificateFile = Path.GetTempFileName();

        try
        {
            string publicCert = issuer.ExportCertificatePem();
            File.WriteAllText(certificateFile, publicCert);

            var timeProvider = TimeProvider.System;
            var localSettings = new TlsProbeOptions
            {
                Timeout = TimeSpan.FromSeconds(5),
                TrustMode = TrustMode.CustomRoots,
                TrustConfigurationId = "test-root-ca",
                RootCertificatePaths = [certificateFile]
            };

            var options = Options.Create(localSettings);

            var addresses = new IPAddress[] { IPAddress.IPv6Loopback, IPAddress.Loopback };
            var sut = new TlsProbe(timeProvider, options, new FixedHostResolver(addresses));

            await using TlsTestServer testServer = new TlsTestServer(issuer);
            var request = new TlsProbeRequest("localhost", testServer.Port);

            var result = await sut.ProbeAsync(request);
            
            Assert.Equal(CheckOutcome.Passed, result.DnsResolution);
            Assert.Equal(CheckOutcome.Passed, result.TcpConnection);
            Assert.Equal(CheckOutcome.Passed, result.TlsAuthentication);
            Assert.Equal(CheckOutcome.Passed, result.CertificateValidation);

            Assert.NotNull(result.Connection);
            Assert.NotNull(result.Certificate);
            Assert.Equal(IPAddress.Loopback.ToString(), result.Connection.RemoteIpAddress);
            Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Issuer));
            Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Subject));
            Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Sha256Fingerprint));

            Assert.NotEqual(default, result.Certificate.NotAfter);
            Assert.NotEqual(default, result.Certificate.NotBefore);

            Assert.False(string.IsNullOrWhiteSpace(result.Connection.TlsProtocol));
            Assert.False(string.IsNullOrWhiteSpace(result.Connection.CipherSuite));

            Assert.True(result.Certificate.NotAfter > result.Certificate.NotBefore);
            Assert.Equal(TrustMode.CustomRoots, result.TrustContext.Mode);
            Assert.Equal(localSettings.TrustConfigurationId, result.TrustContext.ConfigurationId);
            Assert.Contains(issuer.GetCertHashString(HashAlgorithmName.SHA256),
                result.TrustContext.RootSha256Fingerprints);
            Assert.Contains(result.Findings, f => f.Code == "TCP_CONNECTION_FAILED" && 
                                                  f.Message.Contains("::1"));
            Assert.DoesNotContain(result.Findings, f => f.Code.StartsWith("CERT_"));
            Assert.DoesNotContain(result.Findings, f => f.Code.StartsWith("TLS_"));
        }
        finally
        {
            File.Delete(certificateFile);
        }
    }

    [Fact]
    public async Task ProbeAsync_WithExpiredTrustedServerCertificate_ReturnsValidationFailure()
    {
        using var issuer = TlsTestServer.CreateCertificateAuthority();

        var certificateFile = Path.GetTempFileName();

        try
        {
            string publicCert = issuer.ExportCertificatePem();
            File.WriteAllText(certificateFile, publicCert);
            
            var timeProvider = TimeProvider.System;
            var now = timeProvider.GetUtcNow();
            
            var localSettings = new TlsProbeOptions
            {
                Timeout = TimeSpan.FromSeconds(5),
                TrustMode = TrustMode.CustomRoots,
                TrustConfigurationId = "test-root-ca",
                RootCertificatePaths = [certificateFile]
            };

            var options = Options.Create(localSettings);
            var sut = new TlsProbe(timeProvider, options, new SystemHostResolver());

            await using TlsTestServer testServer = new TlsTestServer(
                issuer, 
                certificateHostname: "localhost", 
                certificateNotBefore: now.AddDays(-2),
                certificateNotAfter: now.AddDays(-1));
            var request = new TlsProbeRequest("localhost", testServer.Port);
            
            var result = await sut.ProbeAsync(request);
            
            Assert.Equal(CheckOutcome.Passed, result.DnsResolution);
            Assert.Equal(CheckOutcome.Passed, result.TcpConnection);
            Assert.Equal(CheckOutcome.Failed, result.TlsAuthentication);
            Assert.Equal(CheckOutcome.Failed, result.CertificateValidation);
            
            Assert.NotNull(result.Connection);
            Assert.NotNull(result.Certificate);
            Assert.False(string.IsNullOrWhiteSpace(result.Connection.RemoteIpAddress));
            Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Issuer));
            Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Subject));
            Assert.False(string.IsNullOrWhiteSpace(result.Certificate.Sha256Fingerprint));
            
            Assert.NotEqual(default, result.Certificate.NotAfter);
            Assert.True(result.Certificate.NotAfter < result.TrustContext.EvaluationTime);
            Assert.NotEqual(default, result.Certificate.NotBefore);

            Assert.True(result.Certificate.NotAfter > result.Certificate.NotBefore);
            Assert.Equal(TrustMode.CustomRoots, result.TrustContext.Mode);
            Assert.Equal(localSettings.TrustConfigurationId, result.TrustContext.ConfigurationId);
            Assert.Contains(issuer.GetCertHashString(HashAlgorithmName.SHA256), result.TrustContext.RootSha256Fingerprints);
            Assert.Contains(result.Findings, f => f.Code == "CERT_CHAIN_INVALID" && f.Message.Contains("NotTimeValid"));
            Assert.Contains(result.Findings, f => f.Code == "TLS_AUTHENTICATION_FAILED");
            Assert.DoesNotContain(result.Findings, f => f.Code == "CERT_HOSTNAME_MISMATCH");
        }
        finally
        {
            File.Delete(certificateFile);
        }
    }
    
    private static int GetUnusedLoopBackPort()
    {
        using var listener = new TcpListener(localaddr: IPAddress.Loopback, port: 0);
        listener.Start();
        try
        {
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }
}