# 01 Valid Server TLS

## Purpose:
- Establish a successful, validated TLS connection and display verification output.

## Setup:
- Server: The Lab server, is a web server running in Docker.
- Client: The client is initially curl on the local machine.
- Endpoint: Endpoint URL is https://localhost:8443.
- Certificate authority: CA is a locally generated lab root CA.
- Server certificate: Local root CA issues server certificate with DNS:localhost in the Subject Alternative Name.
- Client trust: The root CA's public certificate is supplied explicitly to curl for this request. The machine's global trust configuration remains unchanged.
- Authentication: The client validates the server certificate. The server does not request a client certificate.

## Expected result:
- The client trusts the chain, the hostname matches, and the HTTPS request succeeds.

## Evidence:
- Record the command, certificate verification output, HTTP status and response body after execution.

## Cleanup:
- Stop and remove the lab containers using Docker Compose.