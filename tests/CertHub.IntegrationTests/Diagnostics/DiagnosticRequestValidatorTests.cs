using CertHub.Api.Features.Diagnostics;

namespace CertHub.IntegrationTests.Diagnostics;

public class DiagnosticRequestValidatorTests
{
    private static readonly string MaxLabel = new string('a', 63);

    public static TheoryData<string> ValidHostnames => new()
    {
        "a",
        MaxLabel,
        $"{MaxLabel}.{MaxLabel}.{MaxLabel}.{new string('a', 61)}"
    };
    
    [Theory]
    [InlineData("localhost")]
    [InlineData("api2.example.com")]
    [InlineData("3service.example")]
    [InlineData("service.123")]
    [InlineData("my-host.com")]
    [MemberData(nameof(ValidHostnames))]
    public void Validate_WithValidRequest_ReturnsNoErrors(string hostname)
    {
        var request = new RunTlsDiagnosticRequest(hostname, 8443);
        var errors = DiagnosticRequestValidator.Validate(request);
        
        Assert.Empty(errors);
    }
    
    [Theory]
    [InlineData(1)]
    [InlineData(65535)]
    public void Validate_WithValidBoundaryPort_ReturnsNoErrors(int port)
    {
        var request = new RunTlsDiagnosticRequest("localhost", port);
        var errors = DiagnosticRequestValidator.Validate(request);
        
        Assert.Empty(errors);
    }
    
    [Fact]
    public void Validate_WithMissingHostnameAndInvalidPort_ReturnsBothErrors()
    {
        var request = new RunTlsDiagnosticRequest("", 0);
        var errors = DiagnosticRequestValidator.Validate(request);

        Assert.Equal(2, errors.Count);
        var hostname = Assert.Single(errors["Hostname"]);
        var port = Assert.Single(errors["Port"]);
        
        Assert.False(string.IsNullOrWhiteSpace(hostname));
        Assert.False(string.IsNullOrWhiteSpace(port));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void Validate_WithMissingHostname_ReturnsHostnameError(string? hostname)
    {
        var request = new RunTlsDiagnosticRequest(hostname!, 80);
        var errors = DiagnosticRequestValidator.Validate(request);
        
        var message = Assert.Single(errors["Hostname"]);
        Assert.False(string.IsNullOrWhiteSpace(message));
    }

    private static readonly string TooLongLabel = new string('a', 64);

    public static TheoryData<string> InvalidHostnames => new()
    {
        TooLongLabel,
        $"{MaxLabel}.{MaxLabel}.{MaxLabel}.{new string('a', 62)}",
        "https://localhost",
        "localhost/path",
        "localhost:8443",
        "127.0.0.1",
        "::1",
        "local host",
        "my_host.com",
        "bad-.com",
        "999.999.999.999",
        "-bad.com",
        "api..example.com",
        "example.com.",
        "123"
    };
    
    [Theory]
    [MemberData(nameof(InvalidHostnames))]
    public void Validate_WithInvalidHostnameFormat_ReturnsHostnameError(string hostname)
    {
        var request = new RunTlsDiagnosticRequest(hostname!, 80);
        var errors = DiagnosticRequestValidator.Validate(request);
        var message = Assert.Single(errors["Hostname"]);
        Assert.False(string.IsNullOrWhiteSpace(message));
    }
    
    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(65536)]
    public void Validate_WithInvalidPort_ReturnsPortError(int port)
    {
        var request = new RunTlsDiagnosticRequest("localhost", port);
        var errors = DiagnosticRequestValidator.Validate(request);
        
        var message = Assert.Single(errors["Port"]);
        Assert.False(string.IsNullOrWhiteSpace(message));
    }
}