namespace CertHub.Infrastructure.Tls;

internal static class TlsExceptionFormatter
{
    private const int MaxDepth = 10;
    
    public static string Format(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        
        var parts = new List<string>();
        Exception? current = exception;
        
        while (current is not null && parts.Count < MaxDepth)
        {
            parts.Add($"{current.GetType().Name}: {current.Message}");
            current = current.InnerException;
        }
        
        if (current is not null)
            parts.Add("[Further inner exceptions omitted]");

        return string.Join(" --> ", parts);
    }
}