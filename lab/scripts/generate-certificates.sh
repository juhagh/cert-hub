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

if [[ -e "$GENERATED_FILES_DIR" || -L "$GENERATED_FILES_DIR" ]]; then
  echo "$GENERATED_FILES_DIR already exists, please rename or move the directory before generating a new set of files." >&2
  exit 1
fi