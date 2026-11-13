using CertHub.Domain.Diagnostics;

namespace CertHub.Infrastructure.Tls;

public sealed class TlsProbeOptions
{
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);
    public TrustMode TrustMode { get; set; } = TrustMode.System;
    public string TrustConfigurationId { get; set; } = "system";
    public string[] RootCertificatePaths { get; set; } = [];
    public string? ClientCertificatePath { get; set; } = null;
    public string? ClientCertificatePassword { get; set; } = null;
    public string[] ApplicationProtocols { get; set; } = [];
}