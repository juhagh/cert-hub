# 06 ALPN Negotiation

## Purpose

Observe the application protocol selected during CertHub's TLS connection to the standard lab server. Compare offers for HTTP/2 and HTTP/1.1, HTTP/1.1 alone, and the default empty offer list.

ALPN (Application-Layer Protocol Negotiation) runs within TLS authentication. CertHub records the negotiated identifier but sends no HTTP request or other application data to the lab target.

## Setup

Follow the [lab setup guide](../README.md) to generate certificates, supply `CERTHUB_LAB_PFX_PASSWORD`, allow `localhost:8443`, and configure the API's custom-root trust for the generated lab CA.

Run commands from the repository root. Multiline commands use Bash/zsh syntax. The API HTTPS profile runs in Development and loads User Secrets; environment and command-line overrides can take precedence.

Use the standard valid-certificate server, without the expired-certificate or mTLS overrides. If an override is active, stop that configuration with its original Compose files before starting the base service:

```bash
docker compose -f lab/compose.yaml up --build -d
```

The Compose password must be set in the calling terminal. Certificates must still be within their validity periods.

There are two separate connections:

- curl calls the CertHub API at `https://localhost:7297` using the ASP.NET Core development certificate.
- CertHub probes `localhost:8443` using its configured lab CA trust and ALPN offers.

A curl option such as `--http1.1` controls the first connection, not the probe's ALPN offers to the target. Configure target offers through `TlsProbe:ApplicationProtocols`.

## 1. Offer HTTP/2 and HTTP/1.1

```bash
dotnet user-secrets set "TlsProbe:ApplicationProtocols:0" "h2" --project src/CertHub.Api
dotnet user-secrets set "TlsProbe:ApplicationProtocols:1" "http/1.1" --project src/CertHub.Api
```

Ensure no additional array entries or other configuration overrides change these two offers. Start or restart the API after each configuration change:

```bash
dotnet run --project src/CertHub.Api/CertHub.Api.csproj --launch-profile https
```

Call the API from another terminal:

```bash
curl --silent --show-error --noproxy '*'   https://localhost:7297/diagnostics/tls   -H 'Content-Type: application/json'   -d '{"hostname":"localhost","port":8443}'   -w '\nHTTP status: %{http_code}\n'
```

The request body supplies hostname and port only. ALPN settings belong to the operator configuration.

## 2. Offer HTTP/1.1 only

```bash
dotnet user-secrets set "TlsProbe:ApplicationProtocols:0" "http/1.1" --project src/CertHub.Api
dotnet user-secrets remove "TlsProbe:ApplicationProtocols:1" --project src/CertHub.Api
```

Restart the API and repeat the same request. This removes `h2` from the offer rather than merely changing its preference.

## 3. Restore the default empty offer list

```bash
dotnet user-secrets remove "TlsProbe:ApplicationProtocols:0" --project src/CertHub.Api
```

With no other sources or array entries supplying protocols, the default is `[]`. Restart the API and repeat the same request.

Successful TLS without ALPN selection is valid for this standard lab configuration. `connection.applicationProtocol` should be null; it does not mean the server negotiated an implicit protocol through ALPN.

## Recorded evidence

The following results were observed on macOS on 13 November 2026. Timestamps are UTC. All three responses returned HTTP `200` with DNS resolution, TCP connection, TLS authentication and certificate validation `Passed`.

| Client offers | Attempted at (UTC) | TLS protocol | Application protocol | TCP-stage duration |
|---|---|---|---|---|
| `h2`, `http/1.1` | `2026-11-13T10:02:23.98853+00:00` | `Tls12` | `h2` | `00:00:00.0044646` |
| `http/1.1` | `2026-11-13T10:05:58.462302+00:00` | `Tls12` | `http/1.1` | `00:00:00.0046051` |
| None | `2026-11-13T10:07:12.893688+00:00` | `Tls12` | JSON `null` | `00:00:00.0043225` |

Common evidence across all three reports:

- Connected address: `127.0.0.1`.
- Cipher suite: `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.
- Server subject: `CN=localhost`; issuer: `CN=CertHub Lab Root CA`.
- Server validity: `2026-11-10T09:52:05+00:00` through `2027-02-08T09:57:05+00:00`.
- Server SHA-256 fingerprint: `C4FC2F0146E531CE98A6B6B4C4164D46CE5EFEF9A918438ADB49B52A789C8905`.
- Server DNS SAN: `localhost`; no IP SAN entries.
- Trust mode: `CustomRoots`; configuration ID: `certhub-lab`.
- Root SHA-256 fingerprint: `59F582D34ED85989AFA861D336C80E7292C2E5F0587E4822546E6AB31749D0FC`.
- Built chain: server leaf followed by the lab root, both with empty status arrays; overall chain status array empty.
- Retained finding: `TCP_CONNECTION_FAILED`, message `::1 - ConnectionRefused: Connection refused`.

The initial IPv6 refusal occurred before successful IPv4 connection. It did not cause the overall TCP stage to fail.

A client credential from an earlier mTLS exercise remained configured in these runs. `configuredClientCertificate` identified `CN=CertHub Lab Client`, fingerprint `AB94EF90452BAE944A31B205E5B6530A98A6B1183079DFD2A01E42B9EEB69423`. That field confirms local credential loading, not selection, transmission or server acceptance. The standard lab does not require client authentication. Reproducing this ALPN scenario does not require configuring a client PFX.

These are recorded diagnostic results, not an HTTP/2 or HTTP/1.1 application exchange with the target. The final run restored the default empty ALPN offer list. Freshly generated certificates will have different dates and fingerprints.

## How protocol selection works

The client advertises protocol identifiers in descending client preference order. An ALPN-enabled server selects a protocol it supports from those offers, normally using its own preference among the shared protocols. Client order is not a guarantee of selection. The first observation establishes that `h2` was selected for those offers; it does not establish a universal server selection policy.

If the client sends no ALPN extension, no application protocol is selected through ALPN. TLS may still succeed, as observed here. Application-specific configuration can provide fallback behaviour; the report's null value does not establish which application protocol would subsequently be used.

If the client offers ALPN but the server does not negotiate it, TLS may likewise succeed without a selected ALPN value. That differs from two ALPN participants having no shared protocol.

When an ALPN-enabled server supports none of the client's offered protocols, RFC 7301 section 3.2 requires a fatal `no_application_protocol` alert. The server must not select an unoffered protocol. This is a TLS authentication failure, not a certificate-expiry or trust failure. In CertHub, negotiated application-protocol evidence remains null on authentication failure; whether server-certificate validation was reached depends on where the handshake stopped.

The no-overlap case was not executed in this manual record. Platform exception wording and the exact diagnostic findings must be recorded from an actual run rather than inferred here.

Reference: [RFC 7301, Protocol Selection](https://www.rfc-editor.org/rfc/rfc7301.html#section-3.2).

## Cleanup

The commands in step 3 remove the two ALPN entries added by this walkthrough. Remove any additional entries or overrides you supplied elsewhere and restart the API before checking default behaviour. Do not remove unrelated settings merely to clean up this scenario.

Stop the API with Ctrl+C. While the lab PFX password is still available, stop the standard server:

```bash
docker compose -f lab/compose.yaml down
```

For temporary lab trust and client-credential settings from other exercises, use the targeted cleanup instructions in the [API guide](../../docs/api/tls-diagnostics.md) and [lab setup guide](../README.md). No system trust-store change is required for this scenario.
