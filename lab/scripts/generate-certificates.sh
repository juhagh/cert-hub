#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTIFICATES_DIR="${SCRIPT_DIR}/../certificates"
GENERATED_FILES_DIR="${CERTIFICATES_DIR}/generated"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl command is required for this script to work. Please install openssl and re-run the script." >&2
  exit 1
fi

if ! x509_help="$(openssl x509 -help 2>&1)"; then
  echo "openssl command check failed." >&2
  exit 1
fi
  
if [[ "$x509_help" != *"-not_before"* || "$x509_help" != *"-not_after"* ]]; then
  echo "Script requires openssl with support for \"-not_before\" and \"-not_after\" options." >&2
  exit 1
fi

if [[ ! -f "${CERTIFICATES_DIR}/localhost.ext.cnf" || ! -r "${CERTIFICATES_DIR}/localhost.ext.cnf" ]]; then
  echo "Certificate extension file is missing or unreadable: ${CERTIFICATES_DIR}/localhost.ext.cnf" >&2
  exit 1
fi

if [[ ! -f "${CERTIFICATES_DIR}/root-ca.ext.cnf" || ! -r "${CERTIFICATES_DIR}/root-ca.ext.cnf" ]]; then
  echo "Root CA extension file is missing or unreadable: ${CERTIFICATES_DIR}/root-ca.ext.cnf" >&2
  exit 1
fi

if [[ -e "$GENERATED_FILES_DIR" || -L "$GENERATED_FILES_DIR" ]]; then
  echo "$GENERATED_FILES_DIR already exists, please rename or move the directory before generating a new set of files." >&2
  exit 1
fi

format_certificate_date() {
  local platform
  platform=$(uname -s)
  
  if [[ $platform == "Darwin" ]]; then
    date -u -r "$1" '+%Y%m%d%H%M%SZ'
  elif [[ $platform == "Linux" ]]; then
    date -u -d "@$1" '+%Y%m%d%H%M%SZ'
  else
    echo "Unknown platform. Script can only be used on macOS or Linux." >&2
    return 1
  fi
}

GENERATION_TIMESTAMP="$(date +%s)"

CA_NOT_BEFORE="$(format_certificate_date "$((GENERATION_TIMESTAMP - 7 * 24 * 60 * 60))")" 
CA_NOT_AFTER="$(format_certificate_date "$((GENERATION_TIMESTAMP + 365 * 24 * 60 * 60))")"
SERVER_NOT_BEFORE="$(format_certificate_date "$((GENERATION_TIMESTAMP - 5 * 60))")"
SERVER_NOT_AFTER="$(format_certificate_date "$((GENERATION_TIMESTAMP + 90 * 24 * 60 * 60))")"
EXPIRED_NOT_BEFORE="$(format_certificate_date "$((GENERATION_TIMESTAMP - 2 * 24 * 60 * 60))")"
EXPIRED_NOT_AFTER="$(format_certificate_date "$((GENERATION_TIMESTAMP - 24 * 60 * 60))")"

umask 077
if ! mkdir "$GENERATED_FILES_DIR"; then
  echo "Failed to create $GENERATED_FILES_DIR directory" >&2
  exit 1
fi

echo "Generating root CA private-key: certhub-lab-root-ca.key.pem."

openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 \
  -aes-256-cbc \
  -out "${GENERATED_FILES_DIR}/certhub-lab-root-ca.key.pem"

echo "Creating the root CA's self-signed certificate: certhub-lab-root-ca.cert.pem."

openssl x509 \
  -new \
  -key "${GENERATED_FILES_DIR}/certhub-lab-root-ca.key.pem" \
  -subj "/CN=CertHub Lab Root CA" \
  -sha256 \
  -not_before "$CA_NOT_BEFORE" \
  -not_after "$CA_NOT_AFTER" \
  -extfile "${CERTIFICATES_DIR}/root-ca.ext.cnf" \
  -extensions root_ca \
  -out "${GENERATED_FILES_DIR}/certhub-lab-root-ca.cert.pem"

echo "Generating the server private key: localhost.key.pem. Choose its passphrase."

openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 \
  -aes-256-cbc \
  -out "${GENERATED_FILES_DIR}/localhost.key.pem"

echo "Creating server certificate signing request: localhost.csr.pem."

openssl req \
  -new \
  -key "${GENERATED_FILES_DIR}/localhost.key.pem" \
  -subj "/CN=localhost" \
  -sha256 \
  -addext "subjectAltName=DNS:localhost" \
  -out "${GENERATED_FILES_DIR}/localhost.csr.pem"

echo "Issuing server certificate: localhost.cert.pem."

openssl x509 \
  -req \
  -in "${GENERATED_FILES_DIR}/localhost.csr.pem" \
  -CA "${GENERATED_FILES_DIR}/certhub-lab-root-ca.cert.pem" \
  -CAkey "${GENERATED_FILES_DIR}/certhub-lab-root-ca.key.pem" \
  -CAcreateserial \
  -sha256 \
  -not_before "$SERVER_NOT_BEFORE" \
  -not_after "$SERVER_NOT_AFTER" \
  -extfile "${CERTIFICATES_DIR}/localhost.ext.cnf" \
  -extensions server_certificate \
  -out "${GENERATED_FILES_DIR}/localhost.cert.pem"

echo "Issuing already expired server certificate: localhost-expired.cert.pem."

openssl x509 \
  -req \
  -in "${GENERATED_FILES_DIR}/localhost.csr.pem" \
  -CA "${GENERATED_FILES_DIR}/certhub-lab-root-ca.cert.pem" \
  -CAkey "${GENERATED_FILES_DIR}/certhub-lab-root-ca.key.pem" \
  -CAcreateserial \
  -sha256 \
  -not_before "$EXPIRED_NOT_BEFORE" \
  -not_after "$EXPIRED_NOT_AFTER" \
  -extfile "${CERTIFICATES_DIR}/localhost.ext.cnf" \
  -extensions server_certificate \
  -out "${GENERATED_FILES_DIR}/localhost-expired.cert.pem"