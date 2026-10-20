using CertHub.Application.Diagnostics;
using CertHub.Application.Diagnostics.RunTlsDiagnostic;

namespace CertHub.Api.Features.Diagnostics;

public static class DiagnosticEndpoints
{
    public static IEndpointRouteBuilder MapDiagnosticEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/diagnostics");
        group.MapPost("/tls", RunTlsDiagnosticAsync);
        
        return endpoints;
    }
    
    private static async Task<IResult> RunTlsDiagnosticAsync(RunTlsDiagnosticRequest request,
        DiagnosticTargetPolicy targetPolicy,
        RunTlsDiagnosticUseCase useCase,
        CancellationToken ct)
    {
        var errors = DiagnosticRequestValidator.Validate(request);
        if (errors is { Count: > 0 })
        {
            return Results.ValidationProblem(errors);
        }

        bool isAllowed = targetPolicy.IsAllowed(request.Hostname, request.Port);
        if (!isAllowed)
        {
            var error = Results.ValidationProblem(new Dictionary<string, string[]>()
                { ["Target"] = ["The requested hostname and port are not allowed."] });

            return error;
        }

        TlsProbeRequest probeRequest = new TlsProbeRequest(request.Hostname, request.Port);

        var report = await useCase.ExecuteAsync(probeRequest, ct);

        return Results.Ok(report);
    }
}