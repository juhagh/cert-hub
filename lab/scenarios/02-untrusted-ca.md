# 02 Untrusted CA

## Purpose

- Demonstrate certificate validation failure when the lab CA is absent from the client’s trust configuration.

## Setup

- Server: CertHub.Lab.Server runs in Docker.
- Client: The client is initially curl on the local machine.
- Endpoint: Endpoint URL is https://localhost:8443.
- Certificate authority: CA is a locally generated lab root CA.
- Server certificate: Local root CA issues server certificate with DNS:localhost in the Subject Alternative Name.
- Client trust: No explicit CA file is supplied. Curl uses its default trust configuration, which does not contain the lab root CA.
- Authentication: The client validates the server certificate. The server does not request a client certificate.

## Expected result

- TCP handshake succeeds, certificate validation fails, and no HTTP request is sent.

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

- Run `curl` command from  the repository root without the `--cacert`:

```bash
curl \
  --verbose \
  https://localhost:8443/
```

## Evidence

- The TCP connection succeeds over IPv4. Certificate validation fails during the TLS handshake, and no HTTP request is sent. Curl exits with code 60. 

Run from  the repository root:

```bash
curl \
  --verbose \
  https://localhost:8443/
```

- Example output from the expected certificate validation failure observed on 7 October 2026.

```text
* Host localhost:8443 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:8443...
* connect to ::1 port 8443 from ::1 port 51832 failed: Connection refused
*   Trying 127.0.0.1:8443...
* Connected to localhost (127.0.0.1) port 8443
* (304) (OUT), TLS handshake, Client hello (1):
*  CAfile: /etc/ssl/cert.pem
...
* SSL certificate problem: unable to get local issuer certificate
* Closing connection
curl: (60) SSL certificate problem: unable to get local issuer certificate
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
```

- Verify exit code immediately after the failing curl command.

```bash
echo $?
```

```text
60
```

- The initial IPv6 connection refusal is expected: Compose publishes the port on IPv4 127.0.0.1 only. Curl then connected successfully over IPv4. The first failure was a TCP connection failure, before TLS began.

## Cleanup

- Stop and remove the lab containers using Docker Compose by running from the repository root:

```bash
docker compose -f lab/compose.yaml down
```