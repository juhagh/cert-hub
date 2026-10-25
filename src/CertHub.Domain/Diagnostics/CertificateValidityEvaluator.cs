using System.Collections.Immutable;

namespace CertHub.Domain.Diagnostics;

public static class CertificateValidityEvaluator
{
    public static ImmutableArray<DiagnosticFinding> Evaluate(CertificateSummary certificate,
        DateTimeOffset evaluationTime)
    {
        var findings = ImmutableArray<DiagnosticFinding>.Empty;
        
        if (certificate.NotAfter < evaluationTime)
        {
            return findings.Add(new DiagnosticFinding(Code: "CERT_EXPIRED", Message: "The server certificate has expired."));
        }

        if (certificate.NotBefore > evaluationTime)
        {
            return findings.Add(new DiagnosticFinding(Code: "CERT_NOT_YET_VALID", Message: "The server certificate is not yet valid."));
        }
        
        return findings;
    }
}