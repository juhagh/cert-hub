namespace CertHub.Application.Diagnostics;

public sealed record TlsProbeRequest(
    string Hostname,
    int Port);