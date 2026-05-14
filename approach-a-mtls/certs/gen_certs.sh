#!/usr/bin/env bash
set -euo pipefail

CERTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Generating certificates in $CERTS_DIR"

# Root CA key and self-signed certificate
openssl genrsa -out "$CERTS_DIR/ca.key" 4096

openssl req -new -x509 -days 3650 -key "$CERTS_DIR/ca.key" \
  -out "$CERTS_DIR/ca.crt" \
  -subj "/C=US/O=SecureTransfer/CN=RootCA"

# Sender key and certificate signed by the Root CA
openssl genrsa -out "$CERTS_DIR/sender.key" 4096

openssl req -new -key "$CERTS_DIR/sender.key" \
  -out "$CERTS_DIR/sender.csr" \
  -subj "/C=US/O=SecureTransfer/CN=sender"

openssl x509 -req -days 365 \
  -in "$CERTS_DIR/sender.csr" \
  -CA "$CERTS_DIR/ca.crt" \
  -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERTS_DIR/sender.crt"

# Receiver key and certificate signed by the Root CA
openssl genrsa -out "$CERTS_DIR/receiver.key" 4096

openssl req -new -key "$CERTS_DIR/receiver.key" \
  -out "$CERTS_DIR/receiver.csr" \
  -subj "/C=US/O=SecureTransfer/CN=receiver"

openssl x509 -req -days 365 \
  -in "$CERTS_DIR/receiver.csr" \
  -CA "$CERTS_DIR/ca.crt" \
  -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERTS_DIR/receiver.crt"

# Remove intermediate CSR files
rm -f "$CERTS_DIR/sender.csr" "$CERTS_DIR/receiver.csr"

echo "Done. Files generated:"
echo "  ca.crt       Root CA certificate"
echo "  ca.key       Root CA private key"
echo "  sender.crt   Sender certificate"
echo "  sender.key   Sender private key"
echo "  receiver.crt Receiver certificate"
echo "  receiver.key Receiver private key"
