using CertHub.Api.Features.Diagnostics;
using CertHub.Application.Abstractions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CertHub.IntegrationTests.Diagnostics;

public sealed class DiagnosticApiFactory : WebApplicationFactory<Program>
{
    public StubTlsProbe Probe { get; } = new StubTlsProbe();
    
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<ITlsProbe>();
            services.AddSingleton<ITlsProbe>(Probe);
            services.PostConfigure<DiagnosticTargetOptions>(options =>
            {
                options.AllowedTargets = [new AllowedDiagnosticTarget() {Hostname = "allowed.example", Port = 443}];
            });
        });
    }
}