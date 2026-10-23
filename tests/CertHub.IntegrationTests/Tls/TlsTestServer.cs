using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertHub.IntegrationTests.Tls;

public sealed class TlsTestServer : IAsyncDisposable
{
    private readonly X509Certificate2 _certificate;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _shutdownCts = new CancellationTokenSource();
    private readonly Task _serverTask;
    
    public int Port { get; }

    public TlsTestServer(
        X509Certificate2? issuer = null, 
        string certificateHostname = "localhost",
        DateTimeOffset? certificateNotBefore = null,
        DateTimeOffset? certificateNotAfter = null)
    {
        if (issuer is null)
        {
            _certificate = CreateServerCertificate(certificateHostname);    
        }
        else
        {
            _certificate = CreateIssuedServerCertificate(certificateHostname, 
                issuer, 
                certificateNotBefore, 
                certificateNotAfter);
        }
        
        _listener = new TcpListener(localaddr: IPAddress.Loopback, port: 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _serverTask = ServeConnectionAsync(_shutdownCts.Token);
    }
    
    public async ValueTask DisposeAsync()
    {
        try
        {
            _shutdownCts.Cancel();
            _listener.Stop();
            await _serverTask;
        }
        catch (OperationCanceledException) when (_shutdownCts.IsCancellationRequested)
        {
            // Cancellation is expected  because disposal requests for cancel.
        }
        finally
        {
            _certificate.Dispose();
            _shutdownCts.Dispose();
        }
    }

    private static X509Certificate2 CreateServerCertificate(string certificateHostname)
    {
        //Generate a public/private key pair.
        using RSA rsa = RSA.Create(2048);

        CertificateRequest request = new CertificateRequest(
            subjectName: $"CN={certificateHostname}",
            key: rsa,
            hashAlgorithm: HashAlgorithmName.SHA256,
            padding: RSASignaturePadding.Pkcs1);

        SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(certificateHostname);
        var extension = sanBuilder.Build();

        request.CertificateExtensions.Add(extension);

        X509BasicConstraintsExtension constraintsExtension = new X509BasicConstraintsExtension(
            certificateAuthority: false,
            hasPathLengthConstraint: false,
            pathLengthConstraint: 0,
            critical: true);
        
        request.CertificateExtensions.Add(constraintsExtension);

        X509KeyUsageExtension keyUsageExtension = new X509KeyUsageExtension(
            keyUsages: X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            critical: true);
        
        request.CertificateExtensions.Add(keyUsageExtension);

        OidCollection oidCollection = new OidCollection();
        oidCollection.Add(new Oid("1.3.6.1.5.5.7.3.1"));

        X509EnhancedKeyUsageExtension enhancedKeyUsageExtension = new X509EnhancedKeyUsageExtension(
            oidCollection, 
            critical: false);
        
        request.CertificateExtensions.Add(enhancedKeyUsageExtension);

        var now = DateTimeOffset.UtcNow;

        return request.CreateSelfSigned(
            notBefore: now.AddMinutes(-5),
            notAfter: now.AddDays(1));
    }
    
    internal static X509Certificate2 CreateCertificateAuthority()
    {
        //Generate a public/private key pair.
        using RSA rsa = RSA.Create(2048);

        CertificateRequest request = new CertificateRequest(
            subjectName: "CN=CertHub Test Root CA",
            key: rsa,
            hashAlgorithm: HashAlgorithmName.SHA256,
            padding: RSASignaturePadding.Pkcs1);

        X509BasicConstraintsExtension constraintsExtension = new X509BasicConstraintsExtension(
            certificateAuthority: true,
            hasPathLengthConstraint: false,
            pathLengthConstraint: 0,
            critical: true);
        
        request.CertificateExtensions.Add(constraintsExtension);

        X509KeyUsageExtension keyUsageExtension = new X509KeyUsageExtension(
            keyUsages: X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
            critical: true);
        
        request.CertificateExtensions.Add(keyUsageExtension);

        var now = DateTimeOffset.UtcNow;

        return request.CreateSelfSigned(
            notBefore: now.AddDays(-7),
            notAfter: now.AddDays(1));
    }

    private static X509Certificate2 CreateIssuedServerCertificate(
        string certificateHostname, 
        X509Certificate2 issuer,
        DateTimeOffset? notBefore,
        DateTimeOffset? notAfter)
    {
        //Generate a public/private key pair.
        using RSA rsa = RSA.Create(2048);

        CertificateRequest request = new CertificateRequest(
            subjectName: $"CN={certificateHostname}",
            key: rsa,
            hashAlgorithm: HashAlgorithmName.SHA256,
            padding: RSASignaturePadding.Pkcs1);

        SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(certificateHostname);
        var extension = sanBuilder.Build();

        request.CertificateExtensions.Add(extension);

        X509BasicConstraintsExtension constraintsExtension = new X509BasicConstraintsExtension(
            certificateAuthority: false,
            hasPathLengthConstraint: false,
            pathLengthConstraint: 0,
            critical: true);
        
        request.CertificateExtensions.Add(constraintsExtension);

        X509KeyUsageExtension keyUsageExtension = new X509KeyUsageExtension(
            keyUsages: X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            critical: true);
        
        request.CertificateExtensions.Add(keyUsageExtension);

        OidCollection oidCollection = new OidCollection();
        oidCollection.Add(new Oid("1.3.6.1.5.5.7.3.1"));

        X509EnhancedKeyUsageExtension enhancedKeyUsageExtension = new X509EnhancedKeyUsageExtension(
            oidCollection, 
            critical: false);
        
        request.CertificateExtensions.Add(enhancedKeyUsageExtension);

        var now = DateTimeOffset.UtcNow;
        
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] = 1;

        using var issuedCertificate = request.Create(
            issuerCertificate: issuer,
            notBefore: notBefore ?? now.AddMinutes(-1),
            notAfter: notAfter ?? now.AddHours(12),
            serialNumber: serial);

        return issuedCertificate.CopyWithPrivateKey(rsa);
    }
    
    private async Task ServeConnectionAsync(CancellationToken ct)
    {
        using var client = await _listener.AcceptTcpClientAsync(ct);
        
        using var stream = new SslStream(
            innerStream: client.GetStream(),
            leaveInnerStreamOpen: true);

        SslServerAuthenticationOptions authenticationOptions = new SslServerAuthenticationOptions();
        authenticationOptions.ServerCertificate = _certificate;
        authenticationOptions.ClientCertificateRequired = false;

        await stream.AuthenticateAsServerAsync(authenticationOptions, ct);
    }
}