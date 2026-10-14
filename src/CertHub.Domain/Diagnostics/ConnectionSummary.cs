namespace CertHub.Domain.Diagnostics;

public sealed record ConnectionSummary(
    string? RemoteIpAddress,
    TimeSpan? TcpConnectDuration,
    string? TlsProtocol,
    string? CipherSuite,
    string? ApplicationProtocol);