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
