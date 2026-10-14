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

    public TlsProbe(TimeProvider timeProvider, IOptions<TlsProbeOptions> options)
    {
        _timeProvider = timeProvider;
        _options = options.Value;
    }
    
    public async Task<TlsDiagnosticReport> ProbeAsync(TlsProbeRequest request, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        
        if (_options.TrustMode != TrustMode.System)
            throw new InvalidOperationException("Only System trust mode is currently supported.");

        var attemptedAt = _timeProvider.GetUtcNow();
        var trustContext = new TrustContext(TrustMode.System, "system", ImmutableArray<string>.Empty, attemptedAt);

        using var timeoutCts = new CancellationTokenSource(_options.Timeout, _timeProvider);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        IPAddress[] addresses;
        
        // DNS Resolution
        try
        {
            addresses = await Dns.GetHostAddressesAsync(request.Hostname, linkedCts.Token);
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
            
            return CreateDnsFailureReport(request, attemptedAt, trustContext, diagnosticFinding);
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
        {
            // timeout cancellation
            ct.ThrowIfCancellationRequested();
            
            var diagnosticFinding = new DiagnosticFinding(
                Code: "DNS_TIMEOUT",
                Message: $"DNS resolution exceeded the diagnostic time budget: {_options.Timeout.ToString()}.");
            
            return CreateDnsFailureReport(request, attemptedAt, trustContext, diagnosticFinding);
        }

        if (addresses.Length == 0)
        {
            ct.ThrowIfCancellationRequested();
            
            var diagnosticFinding = new DiagnosticFinding(
                Code: "DNS_RESOLUTION_FAILED",
                Message: "DNS resolution returned no addresses.");

            return CreateDnsFailureReport(request, attemptedAt, trustContext, diagnosticFinding);
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
                        connectionFindings.ToImmutableArray());
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

                return CreateTcpFailureReport(request, attemptedAt, trustContext, connectionFindings.ToImmutableArray());
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
                TargetHost = request.Hostname
            };

            X509ChainPolicy chainPolicy = new()
            {
                DisableCertificateDownloads = true,
                RevocationMode = X509RevocationMode.NoCheck,
                TrustMode = X509ChainTrustMode.System,
                VerificationTime = attemptedAt.UtcDateTime,
                ApplicationPolicy = { new Oid("1.3.6.1.5.5.7.3.1") }
            };

            authenticationOptions.CertificateChainPolicy = chainPolicy;

            CertificateSummary? certificateSummary = null;
            CheckOutcome certificateValidation = CheckOutcome.NotEvaluated;
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

                connectionSummary = connectionSummary with { CipherSuite = cipherSuite, TlsProtocol = tlsProtocol };
                
                ImmutableArray<DiagnosticFinding> findings =
                [
                    .. connectionFindings, .. certificateFindings
                ];
                
                return new TlsDiagnosticReport(
                    request.Hostname,
                    request.Port,
                    attemptedAt,
                    DnsResolution: CheckOutcome.Passed,
                    TcpConnection: CheckOutcome.Passed,
                    TlsAuthentication: CheckOutcome.Passed,
                    CertificateValidation: certificateValidation,
                    Connection: connectionSummary,
                    Certificate: certificateSummary,
                    TrustContext: trustContext,
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
                
                return new TlsDiagnosticReport(
                    request.Hostname,
                    request.Port,
                    attemptedAt,
                    DnsResolution: CheckOutcome.Passed,
                    TcpConnection: CheckOutcome.Passed,
                    TlsAuthentication: CheckOutcome.Failed,
                    CertificateValidation: certificateValidation,
                    Connection: connectionSummary,
                    Certificate: certificateSummary,
                    TrustContext: trustContext,
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
                
                return new TlsDiagnosticReport(
                    request.Hostname,
                    request.Port,
                    attemptedAt,
                    DnsResolution: CheckOutcome.Passed,
                    TcpConnection: CheckOutcome.Passed,
                    TlsAuthentication: CheckOutcome.Failed,
                    CertificateValidation: certificateValidation,
                    Connection: connectionSummary,
                    Certificate: certificateSummary,
                    TrustContext: trustContext,
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
                
                return new TlsDiagnosticReport(
                    request.Hostname,
                    request.Port,
                    attemptedAt,
                    DnsResolution: CheckOutcome.Passed,
                    TcpConnection: CheckOutcome.Passed,
                    TlsAuthentication: CheckOutcome.Failed,
                    CertificateValidation: certificateValidation,
                    Connection: connectionSummary,
                    Certificate: certificateSummary,
                    TrustContext: trustContext,
                    findings);
            }
        }
        finally
        {
            connectedClient?.Dispose();
        }
    }

    private static CertificateSummary CreateCertificateSummary(X509Certificate2 certificate)
    {
        return new CertificateSummary(
            Subject: certificate.Subject,
            Issuer: certificate.Issuer,
            NotBefore: certificate.NotBefore.ToUniversalTime(),
            NotAfter: certificate.NotAfter.ToUniversalTime(),
            Sha256Fingerprint: certificate.GetCertHashString(HashAlgorithmName.SHA256));
    }
    
    private static TlsDiagnosticReport CreateDnsFailureReport(
        TlsProbeRequest request,
        DateTimeOffset attemptedAt,
        TrustContext trustContext,
        DiagnosticFinding finding)
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
            trustContext,
            findings);
    }

    private static TlsDiagnosticReport CreateTcpFailureReport(
        TlsProbeRequest request,
        DateTimeOffset attemptedAt,
        TrustContext trustContext,
        ImmutableArray<DiagnosticFinding> diagnosticFindings)
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
            trustContext,
            diagnosticFindings);
    }
}