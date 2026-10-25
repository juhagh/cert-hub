# 01 Valid Server TLS

## Purpose

- Establish a successful, validated TLS connection and display verification output.

## Setup

- Server: CertHub.Lab.Server runs in Docker.
- Client: The client is initially curl on the local machine.
- Endpoint: Endpoint URL is https://localhost:8443.
- Certificate authority: CA is a locally generated lab root CA.
- Server certificate: Local root CA issues server certificate with DNS:localhost in the Subject Alternative Name.
- Client trust: The root CA's public certificate is supplied explicitly to curl for this request. The machine's global trust configuration remains unchanged.
- Authentication: The client validates the server certificate. The server does not request a client certificate.

## Expected result

- The client trusts the chain, the hostname matches, and the HTTPS request succeeds.

## Run

Follow the [lab setup guide](../README.md) to generate the certificate set and supply `CERTHUB_LAB_PFX_PASSWORD` in the terminal used for Compose. Reuse an existing generated set if the CA and valid server certificate are still valid; the generator deliberately refuses to overwrite it.

Run the following commands from the repository root. Use the base Compose configuration, which mounts the valid `localhost.pfx`. If the expired override is currently running, stop it using both Compose files before switching back to the base configuration.

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

- Run `curl` command from  the repository root:

```bash
curl \
  --verbose \
  --cacert lab/certificates/generated/certhub-lab-root-ca.cert.pem \
  https://localhost:8443/
```

## Evidence

The following is a historical verification record. A newly generated certificate set has different validity dates and fingerprints; the recorded values are not prerequisites for this scenario.

- The check negotiated TLS 1.3, validated the certificate against the supplied lab CA, matched localhost, and received HTTP 200 with Hello World!.

Run from  the repository root:

```bash
curl \
  --verbose \
  --cacert lab/certificates/generated/certhub-lab-root-ca.cert.pem \
  https://localhost:8443/
```

- Example output from the successful run on 7 October 2026.

```text
* Host localhost:8443 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:8443...
* connect to ::1 port 8443 from ::1 port 51698 failed: Connection refused
*   Trying 127.0.0.1:8443...
* Connected to localhost (127.0.0.1) port 8443
...
* SSL connection using TLSv1.3 / AEAD-AES256-GCM-SHA384 / [blank] / UNDEF
* Server certificate:
*  subject: CN=localhost
*  start date: Oct  7 04:38:12 2026 GMT
*  expire date: Jan  5 04:38:12 2027 GMT
*  subjectAltName: host "localhost" matched cert's "localhost"
*  issuer: CN=CertHub Lab Root CA
*  SSL certificate verify ok.
...
< HTTP/2 200 
< content-type: text/plain; charset=utf-8
< date: Wed, 07 Oct 2026 08:32:38 GMT
< server: Kestrel
< 
* Connection #0 to host localhost left intact
Hello World!
```

- The initial IPv6 connection refusal is expected: Compose publishes the port on IPv4 127.0.0.1 only. Curl then connected successfully over IPv4. The first failure was a TCP connection failure, before TLS began.

## Cleanup

- Stop and remove the lab containers using Docker Compose by running from the repository root:

```bash
docker compose -f lab/compose.yaml down
```
