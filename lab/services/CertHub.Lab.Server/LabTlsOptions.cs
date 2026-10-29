namespace CertHub.Lab.Server;

public sealed class LabTlsOptions
{
    public bool RequireClientCertificate { get; set; } = false;
    public string? ClientTrustRootPath { get; set; } = null;
}