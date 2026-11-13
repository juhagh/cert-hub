using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertHub.IntegrationTests.Tls;

public sealed class TlsTestServer : IAsyncDisposable
{
    private readonly X509Certificate2 _certificate;
    private readonly X509Certificate2? _clientTrustRoot;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _shutdownCts = new CancellationTokenSource();
    private readonly Task _serverTask;
    private readonly SslApplicationProtocol[]? _applicationProtocols;
    private readonly bool _allowAuthenticationFailure;
    
    public int Port { get; }

    private readonly TaskCompletionSource<string> _authenticatedClientFingerprint = 
        new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<bool> _clientAuthenticationResult =
        new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<string> _presentedClientFingerprint =
        new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

    public Task<string> AuthenticatedClientFingerprint => _authenticatedClientFingerprint.Task;
    public Task<bool> ClientAuthenticationResult => _clientAuthenticationResult.Task;
    public Task<string> PresentedClientFingerprint => _presentedClientFingerprint.Task;
    
    public TlsTestServer(
        X509Certificate2? issuer = null,
        string certificateHostname = "localhost",
        DateTimeOffset? certificateNotBefore = null,
        DateTimeOffset? certificateNotAfter = null,
        X509Certificate2? clientTrustRoot = null,
        string[]? certificateDnsNames = null,
        IPAddress[]? certificateIpAddresses = null,
        SslApplicationProtocol[]? applicationProtocols = null,
        bool allowAuthenticationFailure = false)
    {
        if (issuer is null)
        {
            _certificate = CreateServerCertificate(
                certificateHostname,
                certificateDnsNames,
                certificateIpAddresses);    
        }
        else
        {
            _certificate = CreateIssuedServerCertificate(
                certificateHostname, 
                issuer,
                certificateNotBefore, 
                certificateNotAfter,
                certificateDnsNames,
                certificateIpAddresses);
        }
        
        _clientTrustRoot = clientTrustRoot;
        _listener = new TcpListener(localaddr: IPAddress.Loopback, port: 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _applicationProtocols = applicationProtocols;
        _allowAuthenticationFailure = allowAuthenticationFailure;
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

    private static X509Certificate2 CreateServerCertificate(
        string certificateHostname,
        string[]? certificateDnsNames,
        IPAddress[]? certificateIpAddresses)
    {
        //Generate a public/private key pair.
        using RSA rsa = RSA.Create(2048);

        CertificateRequest request = new CertificateRequest(
            subjectName: $"CN={certificateHostname}",
            key: rsa,
            hashAlgorithm: HashAlgorithmName.SHA256,
            padding: RSASignaturePadding.Pkcs1);

        SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
        
        string[] dnsNames = certificateDnsNames ?? [certificateHostname];
        IPAddress[] ipAddresses = certificateIpAddresses ?? Array.Empty<IPAddress>();
        
        foreach (var dnsName in dnsNames)
        {
            sanBuilder.AddDnsName(dnsName);
        }
        
        foreach (var ipAddress in ipAddresses)
        {
            sanBuilder.AddIpAddress(ipAddress);
        }

        if (dnsNames.Length > 0 || ipAddresses.Length > 0)
        {
            var extension = sanBuilder.Build();
            request.CertificateExtensions.Add(extension);
        }

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

        OidCollection oidCollection = new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") };

        X509EnhancedKeyUsageExtension enhancedKeyUsageExtension = new X509EnhancedKeyUsageExtension(
            oidCollection, 
            critical: false);
        
        request.CertificateExtensions.Add(enhancedKeyUsageExtension);

        var now = DateTimeOffset.UtcNow;

        return request.CreateSelfSigned(
            notBefore: now.AddMinutes(-5),
            notAfter: now.AddDays(1));
    }

    private static X509Certificate2 CreateIssuedServerCertificate(
        string certificateHostname, 
        X509Certificate2 issuer,
        DateTimeOffset? notBefore,
        DateTimeOffset? notAfter,
        string[]? certificateDnsNames,
        IPAddress[]? certificateIpAddresses)
    {
        //Generate a public/private key pair.
        using RSA rsa = RSA.Create(2048);

        CertificateRequest request = new CertificateRequest(
            subjectName: $"CN={certificateHostname}",
            key: rsa,
            hashAlgorithm: HashAlgorithmName.SHA256,
            padding: RSASignaturePadding.Pkcs1);

        SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
        
        string[] dnsNames = certificateDnsNames ?? [certificateHostname];
        IPAddress[] ipAddresses = certificateIpAddresses ?? Array.Empty<IPAddress>();
        
        foreach (var dnsName in dnsNames)
        {
            sanBuilder.AddDnsName(dnsName);
        }
        
        foreach (var ipAddress in ipAddresses)
        {
            sanBuilder.AddIpAddress(ipAddress);
        }

        if (dnsNames.Length > 0 || ipAddresses.Length > 0)
        {
            var extension = sanBuilder.Build();
            request.CertificateExtensions.Add(extension);
        }
        
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

        OidCollection oidCollection = new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") };

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

        SslServerAuthenticationOptions authenticationOptions = new SslServerAuthenticationOptions
            {
                ServerCertificate = _certificate,
                ClientCertificateRequired = _clientTrustRoot is not null,
                ApplicationProtocols = _applicationProtocols?.ToList()
            };

        if (_clientTrustRoot is not null)
        {
            authenticationOptions.RemoteCertificateValidationCallback = ValidateClientCertificate;
        }

        try
        {
            await stream.AuthenticateAsServerAsync(authenticationOptions, ct);
            
            if (_clientTrustRoot is not null)
            {
                if (stream.RemoteCertificate is not null)
                {
                    _clientAuthenticationResult.TrySetResult(true);
            
                    var certificateFingerprint = stream.RemoteCertificate.GetCertHashString(HashAlgorithmName.SHA256);
                    _authenticatedClientFingerprint.TrySetResult(certificateFingerprint);
                }
                else
                {
                    _clientAuthenticationResult.TrySetResult(false);
                }
            }
        }
        catch (AuthenticationException) when (_clientTrustRoot is not null)
        {
            _clientAuthenticationResult.TrySetResult(false);
        }
        catch (AuthenticationException) when (_allowAuthenticationFailure)
        {
            // This test explicitly permits server-side handshake rejection.
        }
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

    internal static X509Certificate2 CreateIssuedClientCertificate(X509Certificate2 issuer)
    {
        // Generate a public/private key pair.
        using RSA rsa = RSA.Create(2048);

        CertificateRequest request = new CertificateRequest(
            subjectName: "CN=CertHub Test Client",
            key: rsa,
            hashAlgorithm: HashAlgorithmName.SHA256,
            padding: RSASignaturePadding.Pkcs1);

        X509BasicConstraintsExtension constraintsExtension = new X509BasicConstraintsExtension(
            certificateAuthority: false,
            hasPathLengthConstraint: false,
            pathLengthConstraint: 0,
            critical: true);
        
        request.CertificateExtensions.Add(constraintsExtension);

        X509KeyUsageExtension keyUsageExtension = new X509KeyUsageExtension(
            keyUsages: X509KeyUsageFlags.DigitalSignature,
            critical: true);
        
        request.CertificateExtensions.Add(keyUsageExtension);

        OidCollection oidCollection = new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") };

        X509EnhancedKeyUsageExtension enhancedKeyUsageExtension = new X509EnhancedKeyUsageExtension(
            oidCollection, 
            critical: false);
        
        request.CertificateExtensions.Add(enhancedKeyUsageExtension);

        var now = DateTimeOffset.UtcNow;
        
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] = 1;

        using var issuedCertificate = request.Create(
            issuerCertificate: issuer,
            notBefore: now.AddMinutes(-1),
            notAfter: now.AddHours(12),
            serialNumber: serial);

        return issuedCertificate.CopyWithPrivateKey(rsa);
    }
    
    private bool ValidateClientCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        if (_clientTrustRoot is null || certificate is null)
        {
            return false;
        }

        using var clientCertificate = new X509Certificate2(certificate);

        _presentedClientFingerprint.TrySetResult(clientCertificate.GetCertHashString(HashAlgorithmName.SHA256));
        
        using var validationChain = new X509Chain();
        validationChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        validationChain.ChainPolicy.CustomTrustStore.Add(_clientTrustRoot);
        validationChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        validationChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        validationChain.ChainPolicy.DisableCertificateDownloads = true;
        validationChain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
        
        return validationChain.Build(clientCertificate);
    }
}