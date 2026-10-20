using Microsoft.Extensions.Options;

namespace CertHub.Api.Features.Diagnostics;

public sealed class DiagnosticTargetPolicy
{
    private readonly DiagnosticTargetOptions _options;

    public DiagnosticTargetPolicy(IOptions<DiagnosticTargetOptions> options)
    {
        _options = options.Value;
    }

    public bool IsAllowed(string hostname, int port)
    {
        var allowedTargets = _options.AllowedTargets;
        foreach (var allowedTarget in allowedTargets)
        {
            if (string.Equals(allowedTarget.Hostname, hostname, StringComparison.OrdinalIgnoreCase) &&
                allowedTarget.Port == port)
            {
                return true;
            }
        }
        return false;
    }

}