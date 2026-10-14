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

    public TlsTestServer()
    {
        _certificate = CreateServerCertificate();
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

    private static X509Certificate2 CreateServerCertificate()
    {
        //Generate a public/private key pair.
        using RSA rsa = RSA.Create(2048);

        CertificateRequest request = new CertificateRequest(
            subjectName: "CN=localhost",
            key: rsa,
            hashAlgorithm: HashAlgorithmName.SHA256,
            padding: RSASignaturePadding.Pkcs1);

        SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("localhost");
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