FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

WORKDIR /src

COPY lab/services/CertHub.Lab.Server/CertHub.Lab.Server.csproj lab/services/CertHub.Lab.Server/

RUN dotnet restore lab/services/CertHub.Lab.Server/CertHub.Lab.Server.csproj

COPY . .

RUN dotnet publish lab/services/CertHub.Lab.Server/CertHub.Lab.Server.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

COPY --from=build /app/publish .

USER app

EXPOSE 8443
ENTRYPOINT ["dotnet", "CertHub.Lab.Server.dll"]