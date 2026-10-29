using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertHub.Lab.Server;
using Microsoft.AspNetCore.Server.Kestrel.Https;

var builder = WebApplication.CreateBuilder(args);

var labTlsOptions = builder.Configuration
    .GetSection("LabTls")
    .Get<LabTlsOptions>()
    ?? new LabTlsOptions();

if (labTlsOptions.RequireClientCertificate && string.IsNullOrWhiteSpace(labTlsOptions.ClientTrustRootPath))
{
    throw new InvalidOperationException("Client trust path cannot be empty when client certificate is required.");
}

using X509Certificate2? clientTrustRoot = labTlsOptions.RequireClientCertificate
    ? X509CertificateLoader.LoadCertificateFromFile(labTlsOptions.ClientTrustRootPath!)
    : null;

if (labTlsOptions.RequireClientCertificate)
{
    builder.WebHost.ConfigureKestrel(serverOptions =>
    {
        serverOptions.ConfigureHttpsDefaults(httpsOptions =>
        {
            httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            httpsOptions.ClientCertificateValidation = ValidateClientCertificate;
        });
    });
}

var app = builder.Build();

app.MapGet("/", () => "Hello World!");

app.Run();

bool ValidateClientCertificate(X509Certificate2 certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
{
    // clientTrustRoot is captured by ValidateClientCertificate, which Kestrel
    // invokes during TLS handshakes. With top-level statements, this `using` disposes the
    // certificate only after app.Run() returns and the IDE's "captured variable is disposed in the outer scope" warning
    // is a false positive here.
    if (clientTrustRoot is null)
    {
        return false;
    }
    
    using var validationChain = new X509Chain();
    validationChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    validationChain.ChainPolicy.CustomTrustStore.Add(clientTrustRoot); // I get "Captured variable is disposed in the outer scope"
    validationChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
    validationChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    validationChain.ChainPolicy.DisableCertificateDownloads = true;
    validationChain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));

    return validationChain.Build(certificate);
}