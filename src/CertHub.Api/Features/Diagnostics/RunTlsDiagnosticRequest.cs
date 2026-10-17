namespace CertHub.Api.Features.Diagnostics;

public sealed record RunTlsDiagnosticRequest(string Hostname, int Port);