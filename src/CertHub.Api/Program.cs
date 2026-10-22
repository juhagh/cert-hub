using System.Text.Json.Serialization;
using CertHub.Api.Features.Diagnostics;
using CertHub.Application.Abstractions;
using CertHub.Application.Diagnostics.RunTlsDiagnostic;
using CertHub.Infrastructure.Tls;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);
builder.Services.AddSingleton<IHostResolver, SystemHostResolver>();
builder.Services.AddScoped<ITlsProbe, TlsProbe>();
builder.Services.AddScoped<RunTlsDiagnosticUseCase>();
builder.Services.AddScoped<DiagnosticTargetPolicy>();

builder.Services.AddOptions<TlsProbeOptions>()
    .BindConfiguration("TlsProbe");
builder.Services.AddOptions<DiagnosticTargetOptions>()
    .BindConfiguration("DiagnosticTargets");

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

var app = builder.Build();

app.MapDiagnosticEndpoints();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.Run();

public partial class Program
{
    
}