using CertHub.Domain.Diagnostics;

namespace CertHub.Domain.Tests.Diagnostics;

public sealed class CertificateValidityEvaluatorTests
{
    [Theory]
    [InlineData("2026-10-25T03:00:00Z", "2026-10-26T02:00:00Z", "2026-10-25T02:00:00Z", "CERT_NOT_YET_VALID")]
    [InlineData("2026-10-24T02:00:00Z", "2026-10-25T01:00:00Z", "2026-10-25T02:00:00Z", "CERT_EXPIRED")]
    public void Evaluate_EvaluatedAtOutsideValidityWindow_ShouldHaveOneCertificateFinding(
        DateTimeOffset notBefore, 
        DateTimeOffset notAfter,
        DateTimeOffset evaluatedAt,
        string code)
    {
        var testFingerprint = "test-fingerprint";

        var certificate = new CertificateSummary(
            Subject: "subject",
            Issuer: "issuer",
            NotBefore: notBefore,
            NotAfter: notAfter,
            Sha256Fingerprint: testFingerprint);

        var findings = CertificateValidityEvaluator.Evaluate(certificate, evaluatedAt);

        var finding = Assert.Single(findings);
        Assert.Equal(code, finding.Code);
        Assert.False(string.IsNullOrWhiteSpace(finding.Message));
    }
    
    [Theory]
    [InlineData("2026-10-25T02:00:00Z", "2026-10-26T02:00:00Z", "2026-10-25T02:00:00Z")]
    [InlineData("2026-10-24T02:00:00Z", "2026-10-26T02:00:00Z", "2026-10-25T02:00:00Z")]
    [InlineData("2026-10-24T02:00:00Z", "2026-10-25T02:00:00Z", "2026-10-25T02:00:00Z")]
    public void Evaluate_EvaluatedAtWithinValidityWindow_ShouldHaveNoCertificateFinding(
        DateTimeOffset notBefore, 
        DateTimeOffset notAfter,
        DateTimeOffset evaluatedAt)
    {
        var testFingerprint = "test-fingerprint";

        var certificate = new CertificateSummary(
            Subject: "subject",
            Issuer: "issuer",
            NotBefore: notBefore,
            NotAfter: notAfter,
            Sha256Fingerprint: testFingerprint);

        var findings = CertificateValidityEvaluator.Evaluate(certificate, evaluatedAt);

        Assert.Empty(findings);
    }
}