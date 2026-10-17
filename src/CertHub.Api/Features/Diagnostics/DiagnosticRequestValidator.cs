using System.Net;
using System.Text.RegularExpressions;

namespace CertHub.Api.Features.Diagnostics;

public static class DiagnosticRequestValidator
{
    public static Dictionary<string, string[]> Validate(RunTlsDiagnosticRequest request)
    {
        Dictionary<string, string[]> errors = new Dictionary<string, string[]>();

        var hostnameResult = IsValidHostname(request.Hostname);
        if (!hostnameResult.valid)
        {
            errors["Hostname"] = [hostnameResult.error];
        }
            
        if (request.Port is < 1 or > 65535)
        {
            errors["Port"] = ["Port must be between 1 and 65535."];
        }

        return errors;
    }

    private static (bool valid, string error) IsValidHostname(string hostname)
    {
        if (string.IsNullOrWhiteSpace(hostname))
        {
            return (false, "Hostname cannot be empty");
        }
        
        if (hostname.EndsWith('.'))
        {
            return (false, "Hostname is currently not allowed to have trailing dots.");
        }
        
        // Reject hostname exceeding maximum length of 253
        if (hostname.Length > 253)
        {
            return (false, "Hostname cannot exceed maximum of 253 characters. ");
        }
        
        var labels = hostname.Split('.');
        
        // Reject hostname having other than alphanumeric, '-' and '.' characters.
        if (!Regex.IsMatch(hostname, @"\A[A-Za-z0-9-\.]+\z", RegexOptions.None, TimeSpan.FromSeconds(2)))
        {
            return (false, "Hostname can only include alphanumeric, '-' and '.' characters.");
        }
        
        // Reject hostname that has dot separated groups where any group is longer than 63 char
        // or starts or ends with non-alphanumeric character
        foreach (var label in labels)
        {
            if ((label.Length is <= 0 or > 63) ||
                (!char.IsAsciiLetterOrDigit(label[0]) || !char.IsAsciiLetterOrDigit(label[^1])))
            {
                return (false, "Hostname must be a valid DNS name (e.g. example.com).");
            }
        }

        if (Regex.IsMatch(hostname, @"\A[0-9\.]+\z", RegexOptions.None, TimeSpan.FromSeconds(2)))
        {
            return (false, "Hostname must not be in digits and dots format, e.g. (999.999.999.999).");
        }
        
        // Reject IP literals
        if (IPAddress.TryParse(hostname, out _))
        {
            return (false, "IP literals are not valid hostnames.");
        }

        return (true, string.Empty);
    }
}