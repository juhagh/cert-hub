using System.Security.Authentication;
using CertHub.Infrastructure.Tls;

namespace CertHub.IntegrationTests.Tls;

public sealed class TlsExceptionFormatterTests
{
    [Fact]
    public void TlsExceptionFormatter_SingleException_IsFormattedCorrectly()
    {
        Exception exception = new AuthenticationException("TLS failed");
        
        string formattedException = TlsExceptionFormatter.Format(exception);
        
        Assert.Equal("AuthenticationException: TLS failed", formattedException);
    }

    [Fact]
    public void TlsExceptionFormatter_NestedException_IsFormattedCorrectly()
    {
        Exception exception = new AuthenticationException("TLS failed", new IOException("Connection closed"));
        
        string formattedException = TlsExceptionFormatter.Format(exception);
        
        Assert.Equal("AuthenticationException: TLS failed --> IOException: Connection closed", formattedException);
    }
    
    [Fact]
    public void TlsExceptionFormatter_MaximumNumberOfExceptions_IsFormattedCorrectly()
    {
        Exception innerExceptions = new Exception("Inner exception 9");
        for (int i = 8; i >= 1; i--)
        {
            innerExceptions = new Exception($"Inner exception {i}", innerExceptions);
        }
        Exception exception = new AuthenticationException("TLS failed", innerExceptions);
        
        string formattedException = TlsExceptionFormatter.Format(exception);
        
        var expectedParts = new List<string> { "AuthenticationException: TLS failed" };

        for (int i = 1; i <= 9; i++)
            expectedParts.Add($"Exception: Inner exception {i}");

        var expected = string.Join(" --> ", expectedParts);

        Assert.Equal(expected, formattedException);
    }
    
    [Fact]
    public void TlsExceptionFormatter_ExceedingMaximumNumberOfExceptions_TruncatesOverflow()
    {
        Exception innerException = new Exception("Inner exception 10");

        for (int i = 9; i >= 1; i--)
        {
            innerException = new Exception($"Inner exception {i}", innerException);
        }

        Exception exception = new AuthenticationException("TLS failed", innerException);
        
        string formattedException = TlsExceptionFormatter.Format(exception);
        
        var expectedParts = new List<string> { "AuthenticationException: TLS failed" };

        for (int i = 1; i <= 9; i++)
            expectedParts.Add($"Exception: Inner exception {i}");
        
        expectedParts.Add("[Further inner exceptions omitted]");
        
        var expected = string.Join(" --> ", expectedParts);

        Assert.Equal(expected, formattedException);
    }
}