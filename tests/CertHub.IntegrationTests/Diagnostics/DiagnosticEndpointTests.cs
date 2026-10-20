using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using CertHub.Api.Features.Diagnostics;
using CertHub.Domain.Diagnostics;
using Microsoft.AspNetCore.Mvc.Testing;

namespace CertHub.IntegrationTests.Diagnostics;

public sealed class DiagnosticEndpointTests
{
    [Fact]
    public async Task PostTls_WithInvalidRequest_ReturnsValidationProblemWithoutCallingProbe()
    {
        await using var factory = new DiagnosticApiFactory();
        
        var options = new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        };
        
        using var client = factory.CreateClient(options);

        var request = new RunTlsDiagnosticRequest(Hostname: "", Port: 0);
        using var response = await client.PostAsJsonAsync("/diagnostics/tls", request);
        
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers?.ContentType?.MediaType);
        
        string jsonContent = await response.Content.ReadAsStringAsync();

        using JsonDocument doc = JsonDocument.Parse(jsonContent);
        var hostError = doc.RootElement
            .GetProperty("errors")
            .GetProperty("Hostname")
            .EnumerateArray()
            .Select(x => x.GetString())
            .ToArray();
        
        var portError = doc.RootElement
            .GetProperty("errors")
            .GetProperty("Port")
            .EnumerateArray()
            .Select(x => x.GetString())
            .ToArray();

        var error = Assert.Single(hostError);
        Assert.False(string.IsNullOrWhiteSpace(error));
        
        error = Assert.Single(portError);
        Assert.False(string.IsNullOrWhiteSpace(error));
        
        Assert.Equal(0, factory.Probe.CallCount);
    }
    
    [Fact]
    public async Task PostTls_WithDisallowedTarget_ReturnsValidationProblemWithoutCallingProbe()
    {
        await using var factory = new DiagnosticApiFactory();
        
        var options = new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        };
        
        using var client = factory.CreateClient(options);

        var request = new RunTlsDiagnosticRequest(Hostname: "allowed.example", Port: 8443);
        using var response = await client.PostAsJsonAsync("/diagnostics/tls", request);
        
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers?.ContentType?.MediaType);
        
        string jsonContent = await response.Content.ReadAsStringAsync();

        using JsonDocument doc = JsonDocument.Parse(jsonContent);
        
        var targetError = doc.RootElement
                .GetProperty("errors")
                .GetProperty("Target")
                .EnumerateArray()
                .Select(x => x.GetString())
                .ToArray();

        var error = Assert.Single(targetError);
        Assert.False(string.IsNullOrWhiteSpace(error));
        Assert.Equal(0, factory.Probe.CallCount);
    }

    [Fact]
    public async Task PostTls_WithAllowedTarget_ReturnsDiagnosticReportEvenWhenTlsFails()
    {
        var now = TimeProvider.System.GetUtcNow();
        
        await using var factory = new DiagnosticApiFactory();
        
        
        factory.Probe.ReportToReturn = new TlsDiagnosticReport(
            Hostname: "allowed.example",
            Port: 443,
            DnsResolution: CheckOutcome.Passed,
            TcpConnection: CheckOutcome.Passed,
            TlsAuthentication: CheckOutcome.Failed,
            CertificateValidation: CheckOutcome.Failed,
            AttemptedAt: now,
            Connection: new ConnectionSummary(
                RemoteIpAddress: "192.0.2.1",
                TcpConnectDuration: TimeSpan.FromMilliseconds(100),
                TlsProtocol: null,
                CipherSuite: null,
                ApplicationProtocol: null),
            Certificate: null,
            TrustContext: new TrustContext(
                Mode: TrustMode.System, 
                ConfigurationId: "system",
                RootSha256Fingerprints: [],
                EvaluationTime: now),
            Findings: [new DiagnosticFinding(Code: "CERT_CHAIN_INVALID", Message: "Message")]
        );
        
        var options = new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        };
        
        using var client = factory.CreateClient(options);
    
        var request = new RunTlsDiagnosticRequest(Hostname: "allowed.example", Port: 443);
        using var response = await client.PostAsJsonAsync("/diagnostics/tls", request);
        
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers?.ContentType?.MediaType);
        
        string jsonContent = await response.Content.ReadAsStringAsync();
    
        using JsonDocument doc = JsonDocument.Parse(jsonContent);
        
        Assert.Equal(request.Hostname, doc.RootElement
            .GetProperty("hostname")
            .GetString());
        
        Assert.Equal(request.Port, doc.RootElement
            .GetProperty("port")
            .GetInt32());
        
        Assert.Equal("Passed", doc.RootElement
            .GetProperty("dnsResolution")
            .GetString());
        
        Assert.Equal("Failed", doc.RootElement
            .GetProperty("tlsAuthentication")
            .GetString());

        Assert.Equal("Failed", doc.RootElement
            .GetProperty("certificateValidation")
            .GetString());

        Assert.Contains("CERT_CHAIN_INVALID", doc.RootElement
            .GetProperty("findings")
            .EnumerateArray()
            .Select(element => element.GetProperty("code").GetString()));
            
        Assert.Equal(request.Hostname, factory.Probe.LastRequest?.Hostname);
        Assert.Equal(request.Port, factory.Probe.LastRequest?.Port);
        Assert.Equal(1, factory.Probe.CallCount);
    }
}