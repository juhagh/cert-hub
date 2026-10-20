using CertHub.Api.Features.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CertHub.IntegrationTests.Diagnostics;

public class DiagnosticTargetPolicyTests
{
    [Theory]
    [InlineData("localhost", 8443, true)]
    [InlineData("LOCALHOST", 8443, true)]
    [InlineData("localhost", 443, false)]
    [InlineData("other-host", 8443, false)]
    public void IsAllowed_AllowsOnlyConfiguredHosts(string hostname, int port, bool isAllowed)
    {
        var options = Options.Create(new DiagnosticTargetOptions()
            { AllowedTargets = [new AllowedDiagnosticTarget() { Hostname = "localhost", Port = 8443 }] });
        
        var diagnosticTargetPolicy = new DiagnosticTargetPolicy(options);
        Assert.Equal(isAllowed, diagnosticTargetPolicy.IsAllowed(hostname, port));
    }
    
    [Fact]
    public void IsAllowed_TargetPolicyEnforcesExplicitHostnamePortCombination()
    {
        var options = Options.Create(new DiagnosticTargetOptions()
            { AllowedTargets = [
                new AllowedDiagnosticTarget() { Hostname = "localhost", Port = 443 }, 
                new AllowedDiagnosticTarget() { Hostname = "other-host", Port = 8443 }
            ] });
        
        var diagnosticTargetPolicy = new DiagnosticTargetPolicy(options);
        Assert.False(diagnosticTargetPolicy.IsAllowed("localhost", 8443));
    }
    
    [Fact]
    public void IsAllowed_WithEmptyAllowList_ReturnsFalse()
    {
        var options = Options.Create(new DiagnosticTargetOptions()
            { AllowedTargets = [] });
        
        var diagnosticTargetPolicy = new DiagnosticTargetPolicy(options);
        Assert.False(diagnosticTargetPolicy.IsAllowed("localhost", 8443));
    }
}