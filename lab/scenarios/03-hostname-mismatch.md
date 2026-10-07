# 03 Hostname Mismatch

## Purpose

- Demonstrate certificate validation failure when a trusted certificate is presented for the wrong hostname.

## Setup

- Server: CertHub.Lab.Server runs in Docker.
- Client: The client is initially curl on the local machine.
- Endpoint: Endpoint URL is https://localhost:8443.
- Certificate authority: CA is a locally generated lab root CA.
- Server certificate: Local root CA issues server certificate with DNS:localhost in the Subject Alternative Name.
- Client trust: The root CA's public certificate is supplied explicitly to curl for this request. The machine's global trust configuration remains unchanged.
- Authentication: The client validates the server certificate. The server does not request a client certificate.

## Expected result

- TCP connects successfully, but hostname validation rejects the certificate. Curl sends no HTTP request and exits with code 60.

## Run

- Generate `localhost.pfx` and `certhub-lab-root-ca.cert.pem` under `lab/certificates/generated/`, then set `CERTHUB_LAB_PFX_PASSWORD` to the PFX export password. Reuse the certificates from scenario 01; no regeneration is needed.
- Validate the Compose file from the repository root

```bash
docker compose -f lab/compose.yaml config --quiet
```

- Start the server

```bash
docker compose -f lab/compose.yaml up --build -d
```

- Inspect the server logs

```bash
docker compose -f lab/compose.yaml logs tls-server
```

- Run `curl` command from  the repository root with the `--cacert` and `--resolve`:

```bash
curl \
  --verbose \
  --noproxy "*" \
  --cacert lab/certificates/generated/certhub-lab-root-ca.cert.pem \
  --resolve wrong-host.example:8443:127.0.0.1 \
  https://wrong-host.example:8443/

echo $?
```

## Evidence

- The TCP connection succeeds over IPv4. On the tested curl backend, TLS 1.3 negotiation completes before curl reports the hostname mismatch. Curl rejects the connection before sending an HTTP request and exits with code 60.

- Example output from the expected certificate validation failure observed on 7 October 2026.

```text
* Added wrong-host.example:8443:127.0.0.1 to DNS cache
* Hostname wrong-host.example was found in DNS cache
*   Trying 127.0.0.1:8443...
* Connected to wrong-host.example (127.0.0.1) port 8443
...
* (304) (IN), TLS handshake, Finished (20):
* (304) (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / AEAD-AES256-GCM-SHA384 / [blank] / UNDEF
...
*  subjectAltName does not match host name wrong-host.example
* SSL: no alternative certificate subject name matches target host name 'wrong-host.example'
* Closing connection
curl: (60) SSL: no alternative certificate subject name matches target host name 'wrong-host.example'
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
60
```

## Resolution

- Use the correct endpoint identity, `https://localhost:8443/`, with the lab CA supplied.

## Cleanup

- Stop and remove the lab containers using Docker Compose by running from the repository root:

```bash
docker compose -f lab/compose.yaml down
```