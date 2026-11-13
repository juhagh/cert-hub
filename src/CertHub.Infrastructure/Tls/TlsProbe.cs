using System.Collections;
using System.Collections.Immutable;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertHub.Application.Abstractions;
using CertHub.Application.Diagnostics;
using CertHub.Domain.Diagnostics;
using Microsoft.Extensions.Options;

namespace CertHub.Infrastructure.Tls;

public sealed class TlsProbe : ITlsProbe
{

    private readonly TimeProvider _timeProvider;
    private readonly TlsProbeOptions _options;
    private readonly IHostResolver _hostResolver;

    public TlsProbe(TimeProvider timeProvider, IOptions<TlsProbeOptions> options, IHostResolver hostResolver)
    {
        _timeProvider = timeProvider;
        _options = options.Value;
        _hostResolver = hostResolver;
    }
    
    public async Task<TlsDiagnosticReport> ProbeAsync(TlsProbeRequest request, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        
        ValidateOptions();
        
        X509KeyStorageFlags keyStorageFlags = OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet;

        using X509Certificate2? clientCertificate = _options.ClientCertificatePath is not null
            ? X509CertificateLoader.LoadPkcs12FromFile(_options.ClientCertificatePath,
                _options.ClientCertificatePassword,
                keyStorageFlags)
            : null;

        if (clientCertificate is not null && !clientCertificate.HasPrivateKey)
            throw new InvalidOperationException("Client certificate does not include private key.");
        
         
        CertificateSummary? configuredClientCertificate = clientCertificate is null 
            ? null 
            : CreateCertificateSummary(clientCertificate);
        
        var attemptedAt = _timeProvider.GetUtcNow();

        using var timeoutCts = new CancellationTokenSource(_options.Timeout, _timeProvider);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        IPAddress[] addresses;
        X509Certificate2Collection customRoots = new();

        try
        {
            ImmutableArray<string> rootFingerprints = ImmutableArray<string>.Empty;
            
            if (_options.TrustMode == TrustMode.CustomRoots)
            {
                customRoots = LoadCustomTrustRoots(_options.RootCertificatePaths);
                
                rootFingerprints = customRoots
                    .Select(r => r.GetCertHashString(HashAlgorithmName.SHA256))
                    .ToImmutableArray();
            }
            
            var trustContext = new TrustContext(
                Mode: _options.TrustMode, 
                ConfigurationId: _options.TrustMode == TrustMode.System ? "system" : 
                    _options.TrustConfigurationId,
                RootSha256Fingerprints: rootFingerprints,
                EvaluationTime: attemptedAt);
            
            // DNS Resolution
            try
            {
                addresses = await _hostResolver.ResolveAsync(request.Hostname, linkedCts.Token);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // caller cancellation
                throw;
            }
            catch (SocketException ex)
            {
                // Return a report with DNS Failed and a resolution finding
                ct.ThrowIfCancellationRequested();

                var diagnosticFinding = new DiagnosticFinding(
                    Code: "DNS_RESOLUTION_FAILED",
                    Message: $"{ex.SocketErrorCode}: {ex.Message}");
            
                return CreateDnsFailureReport(request, attemptedAt, trustContext, diagnosticFinding, configuredClientCertificate);
            }
            catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
            {
                // timeout cancellation
                ct.ThrowIfCancellationRequested();
            
                var diagnosticFinding = new DiagnosticFinding(
                    Code: "DNS_TIMEOUT",
                    Message: $"DNS resolution exceeded the diagnostic time budget: {_options.Timeout.ToString()}.");
            
                return CreateDnsFailureReport(request, attemptedAt, trustContext, diagnosticFinding, configuredClientCertificate);
            }

            if (addresses.Length == 0)
            {
                ct.ThrowIfCancellationRequested();
            
                var diagnosticFinding = new DiagnosticFinding(
                    Code: "DNS_RESOLUTION_FAILED",
                    Message: "DNS resolution returned no addresses.");

                return CreateDnsFailureReport(request, attemptedAt, trustContext, diagnosticFinding, configuredClientCertificate);
            }
        
            // Continue to TCP
            TcpClient? connectedClient = null;
            List<DiagnosticFinding> connectionFindings = new();

            try
            {
                TimeSpan? tcpConnectDuration = null;
                var tcpStartedAt = _timeProvider.GetTimestamp();
            
                foreach (var address in addresses)
                {
                    var client = new TcpClient(address.AddressFamily);

                    // TCP Connection
                    try
                    {
                        await client.ConnectAsync(address, request.Port, linkedCts.Token);
                        tcpConnectDuration = _timeProvider.GetElapsedTime(tcpStartedAt);
                        connectedClient = client;
                        break;
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
                    {
                        // timeout cancellation
                        ct.ThrowIfCancellationRequested();
                        connectionFindings.Add(
                            new DiagnosticFinding(
                                Code: "TCP_TIMEOUT",
                                Message: $"{address} - Connection attempt exceeded the diagnostic time budget: {_options.Timeout.ToString()}."));

                        return CreateTcpFailureReport(
                            request,
                            attemptedAt,
                            trustContext,
                            connectionFindings.ToImmutableArray(),
                            configuredClientCertificate);
                    }
                    catch (SocketException ex)
                    {
                        ct.ThrowIfCancellationRequested();
                        connectionFindings.Add(
                            new DiagnosticFinding(
                                Code: "TCP_CONNECTION_FAILED",
                                Message: $"{address} - {ex.SocketErrorCode}: {ex.Message}"));
                    }
                    finally
                    {
                        if (client != connectedClient)
                        {
                            client.Dispose();
                        }
                    }
                }

                if (connectedClient is null)
                {
                    // TCP failure report
                    ct.ThrowIfCancellationRequested();

                    return CreateTcpFailureReport(
                        request, 
                        attemptedAt, 
                        trustContext, 
                        connectionFindings.ToImmutableArray(), 
                        configuredClientCertificate);
                }
            
                var remoteEndPoint = connectedClient.Client.RemoteEndPoint as IPEndPoint;

                // TCP Connection Report
                ConnectionSummary connectionSummary = new ConnectionSummary(
                    RemoteIpAddress: remoteEndPoint?.Address.ToString(),
                    TcpConnectDuration: tcpConnectDuration,
                    TlsProtocol: null,
                    CipherSuite: null,
                    ApplicationProtocol: null);

                // TLS Negotiation
                await using var sslStream = new SslStream(connectedClient.GetStream(), leaveInnerStreamOpen: true);
                
                SslClientAuthenticationOptions authenticationOptions = new()
                {
                    TargetHost = request.Hostname,
                    ClientCertificates = clientCertificate is not null ? [clientCertificate] : null,
                    ApplicationProtocols = _options.ApplicationProtocols
                        .Select(protocol => new SslApplicationProtocol(protocol))
                        .ToList()
                };

                X509ChainTrustMode trustMode = _options.TrustMode == TrustMode.System
                    ? X509ChainTrustMode.System
                    : X509ChainTrustMode.CustomRootTrust;
                
                X509ChainPolicy chainPolicy = new()
                {
                    DisableCertificateDownloads = true,
                    RevocationMode = X509RevocationMode.NoCheck,
                    TrustMode = trustMode,
                    VerificationTime = attemptedAt.UtcDateTime,
                    ApplicationPolicy = { new Oid("1.3.6.1.5.5.7.3.1") }
                };

                if (trustMode == X509ChainTrustMode.CustomRootTrust)
                {
                    chainPolicy.CustomTrustStore.AddRange(customRoots);
                }

                authenticationOptions.CertificateChainPolicy = chainPolicy;

                CertificateSummary? certificateSummary = null;
                CheckOutcome certificateValidation = CheckOutcome.NotEvaluated;
                ImmutableArray<string> serverChainStatusCodes = ImmutableArray<string>.Empty;
                ImmutableArray<CertificateChainElement> serverCertificateChain =
                    ImmutableArray<CertificateChainElement>.Empty;
                List<DiagnosticFinding> certificateFindings = new();

                authenticationOptions.RemoteCertificateValidationCallback = ValidateServerCertificate;
         
                bool ValidateServerCertificate(
                    object sender,
                    X509Certificate? certificate,
                    X509Chain? chain,
                    SslPolicyErrors sslPolicyErrors)
                {
                    if (certificate is X509Certificate2 c)
                    {
                        certificateSummary = CreateCertificateSummary(c);
                    }
                    else if (certificate is not null)
                    {
                        var certBytes = certificate.GetRawCertData();
                        using var cert = X509CertificateLoader.LoadCertificate(certBytes);
                        certificateSummary = CreateCertificateSummary(cert);
                    }

                    if (certificateSummary is not null)
                    {
                        var findings = CertificateValidityEvaluator.Evaluate(certificateSummary, attemptedAt);
                        certificateFindings.AddRange(findings);
                    }

                    if (chain is not null)
                    {
                        serverChainStatusCodes = chain.ChainStatus
                            .Select(entry => entry.Status
                            .ToString())
                            .ToImmutableArray();

                        serverCertificateChain = chain.ChainElements
                            .Select(element =>
                                new CertificateChainElement(
                                    Certificate: CreateCertificateSummary(element.Certificate),
                                    StatusCodes: element.ChainElementStatus
                                        .Select(status => status.Status.ToString())
                                        .ToImmutableArray())
                            ).ToImmutableArray();
                    }
                    
                    if (sslPolicyErrors == SslPolicyErrors.None)
                    {
                        certificateValidation = CheckOutcome.Passed;
                        return true;
                    }

                    certificateValidation = CheckOutcome.Failed;
                    if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
                    {
                        certificateFindings.Add(
                            new DiagnosticFinding(
                                Code: "CERT_NOT_PRESENTED",
                                Message: "Certificate not available."));
                    }
                
                    if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
                    {
                        certificateFindings.Add(
                            new DiagnosticFinding(
                                Code: "CERT_HOSTNAME_MISMATCH",
                                Message: $"Certificate name mismatch. Certificate does not match the requested hostname: {request.Hostname}"));
                    }
                
                    if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
                    {
                        var chainStatusTuples = new List<(string Status, string Information)>();
                    
                        if (chain?.ChainStatus.Length > 0)
                        {
                            foreach (var status in chain.ChainStatus)
                            {
                                chainStatusTuples.Add((status.Status.ToString(), status.StatusInformation.Trim()));
                            }
                        }

                        string chainDetails = chainStatusTuples.Count > 0
                            ? string.Join(", ", chainStatusTuples.Select(t => $"[{t.Status}: {t.Information}]"))
                            : "";
                    
                        certificateFindings.Add(
                            new DiagnosticFinding(
                                Code: "CERT_CHAIN_INVALID",
                                Message: $"Chain validation failed under the configured policy. {chainDetails}"));
                    }
                
                    return false;
                }
            
                // Proceed to TLS
                try
                {
                    await sslStream.AuthenticateAsClientAsync(authenticationOptions, linkedCts.Token);
                
                    ct.ThrowIfCancellationRequested();
                
                    // Create TLS success report
                    var tlsProtocol = sslStream.SslProtocol.ToString();
                    var cipherSuite = sslStream.NegotiatedCipherSuite.ToString();

                    connectionSummary = connectionSummary with
                    {
                        CipherSuite = cipherSuite, 
                        TlsProtocol = tlsProtocol,
                        ApplicationProtocol = sslStream.NegotiatedApplicationProtocol == default
                            ? null
                            : sslStream.NegotiatedApplicationProtocol.ToString()
                    };
                
                    ImmutableArray<DiagnosticFinding> findings =
                    [
                        .. connectionFindings, .. certificateFindings
                    ];

                    return CreateTlsReport(
                        request,
                        attemptedAt,
                        trustContext,
                        connectionSummary,
                        certificateSummary,
                        certificateChainElements: serverCertificateChain,
                        serverChainStatusCodes: serverChainStatusCodes,
                        configuredClientCertificate,
                        tlsAuthentication: CheckOutcome.Passed,
                        certificateValidation: certificateValidation,
                        findings);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
                {
                    ct.ThrowIfCancellationRequested();

                    // Create timeout report
                    ImmutableArray<DiagnosticFinding> findings =
                    [
                        .. connectionFindings, .. certificateFindings,
                        new DiagnosticFinding(
                            "TLS_TIMEOUT", 
                            "The shared diagnostic time budget expired during TLS authentication.")
                    ];
                
                    return CreateTlsReport(
                        request,
                        attemptedAt,
                        trustContext,
                        connectionSummary,
                        certificateSummary,
                        certificateChainElements: serverCertificateChain,
                        serverChainStatusCodes: serverChainStatusCodes,
                        configuredClientCertificate,
                        tlsAuthentication: CheckOutcome.Failed,
                        certificateValidation,
                        findings);
                }
                catch (AuthenticationException ex)
                {
                    ct.ThrowIfCancellationRequested();
                    // Create authentication failure report

                    ImmutableArray<DiagnosticFinding> findings =
                    [
                        .. connectionFindings, .. certificateFindings,
                        new DiagnosticFinding("TLS_AUTHENTICATION_FAILED", ex.Message)
                    ];
                
                    return CreateTlsReport(
                        request,
                        attemptedAt,
                        trustContext,
                        connectionSummary,
                        certificateSummary,
                        certificateChainElements: serverCertificateChain,
                        serverChainStatusCodes: serverChainStatusCodes,
                        configuredClientCertificate,
                        tlsAuthentication: CheckOutcome.Failed,
                        certificateValidation,
                        findings);
                }
                catch (IOException ex)
                {
                    ct.ThrowIfCancellationRequested();
                    // Create TLS connection failure report
                
                    ImmutableArray<DiagnosticFinding> findings =
                    [
                        .. connectionFindings, .. certificateFindings,
                        new DiagnosticFinding("TLS_CONNECTION_FAILED", ex.Message)
                    ];
                
                    return CreateTlsReport(
                        request,
                        attemptedAt,
                        trustContext,
                        connectionSummary,
                        certificateSummary,
                        certificateChainElements: serverCertificateChain,
                        serverChainStatusCodes: serverChainStatusCodes,
                        configuredClientCertificate,
                        tlsAuthentication: CheckOutcome.Failed,
                        certificateValidation,
                        findings);
                }
            }
            finally
            {
                connectedClient?.Dispose();
            }
        }
        finally
        {
            foreach (var cert in customRoots)
            {
                cert.Dispose();
            }
        }
    }

    private static X509Certificate2Collection LoadCustomTrustRoots(string[] certificatePaths)
    {
        if (certificatePaths.Length == 0)
        {
            throw new ArgumentException("At least one root certificate required.", nameof(certificatePaths));
        }

        X509Certificate2Collection roots = new();

        try
        {
            foreach (var certificatePath in certificatePaths)
            {
                roots.Add(X509CertificateLoader.LoadCertificateFromFile(certificatePath));
            }
        }
        catch (Exception)
        {
            // Catch any exception and dispose all already loaded certificates.
            foreach (var cert in roots)
            {
                cert.Dispose();
            }

            throw;
        }
        
        return roots;
    }

    private static CertificateSummary CreateCertificateSummary(X509Certificate2 certificate)
    {
        var sanExtension = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().SingleOrDefault();
        var dnsNames = ImmutableArray<string>.Empty;
        var ipAddresses = ImmutableArray<string>.Empty;

        if (sanExtension is not null)
        {
            dnsNames = sanExtension.EnumerateDnsNames().ToImmutableArray();
            ipAddresses = sanExtension.EnumerateIPAddresses().Select(ip => ip.ToString()).ToImmutableArray();
        }
        
        return new CertificateSummary(
            Subject: certificate.Subject,
            Issuer: certificate.Issuer,
            NotBefore: certificate.NotBefore.ToUniversalTime(),
            NotAfter: certificate.NotAfter.ToUniversalTime(),
            Sha256Fingerprint: certificate.GetCertHashString(HashAlgorithmName.SHA256),
            DnsNames: dnsNames,
            IpAddresses: ipAddresses);
    }
    
    private static TlsDiagnosticReport CreateDnsFailureReport(
        TlsProbeRequest request,
        DateTimeOffset attemptedAt,
        TrustContext trustContext,
        DiagnosticFinding finding,
        CertificateSummary? clientCertificateSummary)
    {
        var connectionSummary = new ConnectionSummary(
            RemoteIpAddress: null, 
            TcpConnectDuration: null, 
            TlsProtocol: null, 
            CipherSuite: null, 
            ApplicationProtocol: null);
            
        var findings = ImmutableArray.Create<DiagnosticFinding>(finding);
            
        return new TlsDiagnosticReport(
            request.Hostname,
            request.Port,
            attemptedAt,
            DnsResolution: CheckOutcome.Failed,
            TcpConnection: CheckOutcome.NotEvaluated,
            TlsAuthentication: CheckOutcome.NotEvaluated,
            CertificateValidation: CheckOutcome.NotEvaluated,
            connectionSummary,
            Certificate: null,
            ServerCertificateChain: ImmutableArray<CertificateChainElement>.Empty,
            ServerChainStatusCodes: ImmutableArray<string>.Empty,
            ConfiguredClientCertificate: clientCertificateSummary,
            trustContext,
            findings);
    }

    private static TlsDiagnosticReport CreateTcpFailureReport(
        TlsProbeRequest request,
        DateTimeOffset attemptedAt,
        TrustContext trustContext,
        ImmutableArray<DiagnosticFinding> diagnosticFindings,
        CertificateSummary? clientCertificateSummary)
    {
        var connectionSummary = new ConnectionSummary(
            RemoteIpAddress: null, 
            TcpConnectDuration: null, 
            TlsProtocol: null, 
            CipherSuite: null, 
            ApplicationProtocol: null);
        
        return new TlsDiagnosticReport(
            request.Hostname,
            request.Port,
            attemptedAt,
            DnsResolution: CheckOutcome.Passed,
            TcpConnection: CheckOutcome.Failed,
            TlsAuthentication: CheckOutcome.NotEvaluated,
            CertificateValidation: CheckOutcome.NotEvaluated,
            connectionSummary,
            Certificate: null,
            ServerCertificateChain: ImmutableArray<CertificateChainElement>.Empty,
            ServerChainStatusCodes: ImmutableArray<string>.Empty,
            ConfiguredClientCertificate: clientCertificateSummary,
            trustContext,
            diagnosticFindings);
    }

    private void ValidateOptions()
    {
        if (_options.TrustMode != TrustMode.System && _options.TrustMode != TrustMode.CustomRoots)
            throw new InvalidOperationException("Trust mode must be either System or CustomRoots.");
        
        if (_options.Timeout <= TimeSpan.Zero || _options.Timeout > TimeSpan.FromSeconds(60))
            throw new InvalidOperationException("Timeout value must be greater than 0 and up to 60 seconds.");

        if (_options.TrustMode == TrustMode.CustomRoots)
        {
            if (_options.TrustConfigurationId == "system" || string.IsNullOrWhiteSpace(_options.TrustConfigurationId))
                throw new InvalidOperationException("CustomRoots TrustMode cannot have 'system' as TrustConfigurationId and it cannot be empty." );
        
            if (_options.RootCertificatePaths is null || _options.RootCertificatePaths.Length == 0)
                throw new InvalidOperationException("CustomRoots TrustMode requires at least one certificate path.");

            foreach (var path in _options.RootCertificatePaths)
            {
                if (string.IsNullOrWhiteSpace(path))
                    throw new InvalidOperationException("CustomRoots TrustMode certificate path cannot be empty." );
            }
        }
        
        // ALPN related validation
        if (_options.ApplicationProtocols is null)
            throw new InvalidOperationException("ALPN protocol list cannot be null.");
        
        foreach (var protocol in _options.ApplicationProtocols)
        {
            if (string.IsNullOrWhiteSpace(protocol))
            {
                throw new InvalidOperationException("ALPN entry is null, empty or whitespace.");
            }

            if (protocol.Any(c => c < 32 || c > 126))
            {
                throw new InvalidOperationException("ALPN entry must contain printable ASCII characters only.");
            }

            if (protocol.Length > 255)
            {
                throw new InvalidOperationException("ALPN entry cannot exceed 255 characters.");
            }
        }

        if (_options.ApplicationProtocols.Distinct(StringComparer.Ordinal).Count() != _options.ApplicationProtocols.Length)
        {
            throw new InvalidOperationException("ALPN List contains duplicates.");
        }
        
        // mTLS related validation
        if (_options.ClientCertificatePath is null && _options.ClientCertificatePassword is not null)
            throw new InvalidOperationException("Client certificate password provided, but no certificate path was configured.");
        
        if (_options.ClientCertificatePath is not null && string.IsNullOrWhiteSpace(_options.ClientCertificatePath))
            throw new InvalidOperationException("Client certificate path is empty or white space.");
    }

    private static TlsDiagnosticReport CreateTlsReport(
        TlsProbeRequest request,
        DateTimeOffset attemptedAt,
        TrustContext trustContext,
        ConnectionSummary connection,
        CertificateSummary? serverCertificate,
        ImmutableArray<CertificateChainElement> certificateChainElements,
        ImmutableArray<string> serverChainStatusCodes,
        CertificateSummary? configuredClientCertificate,
        CheckOutcome tlsAuthentication,
        CheckOutcome certificateValidation,
        ImmutableArray<DiagnosticFinding> findings)
    {
        return new TlsDiagnosticReport(
            Hostname: request.Hostname,
            Port: request.Port,
            AttemptedAt: attemptedAt,
            DnsResolution: CheckOutcome.Passed,
            TcpConnection: CheckOutcome.Passed,
            TlsAuthentication: tlsAuthentication,
            CertificateValidation: certificateValidation,
            Connection: connection,
            Certificate: serverCertificate,
            ServerCertificateChain: certificateChainElements,
            ServerChainStatusCodes: serverChainStatusCodes,
            ConfiguredClientCertificate: configuredClientCertificate,
            TrustContext: trustContext,
            Findings: findings);
    }
}