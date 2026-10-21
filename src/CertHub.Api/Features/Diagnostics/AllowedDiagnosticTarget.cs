namespace CertHub.Api.Features.Diagnostics;

public sealed class AllowedDiagnosticTarget
{
    public string Hostname { get; set; } = "";
    public int Port { get; set; } = 0;
}