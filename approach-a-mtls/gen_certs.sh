#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/runtime/certs"

echo "Generating certificates in $CERTS_DIR"

# Root CA key and self-signed certificate
openssl genrsa -out "$CERTS_DIR/ca.key" 4096

openssl req -new -x509 -days 3650 -key "$CERTS_DIR/ca.key" \
  -out "$CERTS_DIR/ca.crt" \
  -subj "/C=US/O=SecureTransfer/CN=RootCA"

# Sender key and certificate signed by the Root CA
# The sender acts as a TLS client so it requires the clientAuth extended key usage
openssl genrsa -out "$CERTS_DIR/sender.key" 4096

openssl req -new -key "$CERTS_DIR/sender.key" \
  -out "$CERTS_DIR/sender.csr" \
  -subj "/C=US/O=SecureTransfer/CN=sender"

cat > "$CERTS_DIR/sender_ext.cnf" << EOF
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -days 365 \
  -in "$CERTS_DIR/sender.csr" \
  -CA "$CERTS_DIR/ca.crt" \
  -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -extfile "$CERTS_DIR/sender_ext.cnf" \
  -out "$CERTS_DIR/sender.crt"

# Receiver key and certificate signed by the Root CA
# The receiver acts as a TLS server so it requires serverAuth and Subject Alternative Names
# DNS:receiver matches the Docker service name and IP:127.0.0.1 covers loopback testing
openssl genrsa -out "$CERTS_DIR/receiver.key" 4096

openssl req -new -key "$CERTS_DIR/receiver.key" \
  -out "$CERTS_DIR/receiver.csr" \
  -subj "/C=US/O=SecureTransfer/CN=receiver"

cat > "$CERTS_DIR/receiver_ext.cnf" << EOF
extendedKeyUsage = serverAuth
subjectAltName   = DNS:receiver,IP:127.0.0.1
EOF

openssl x509 -req -days 365 \
  -in "$CERTS_DIR/receiver.csr" \
  -CA "$CERTS_DIR/ca.crt" \
  -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -extfile "$CERTS_DIR/receiver_ext.cnf" \
  -out "$CERTS_DIR/receiver.crt"

# Remove intermediate files
rm -f "$CERTS_DIR/sender.csr" "$CERTS_DIR/receiver.csr" \
      "$CERTS_DIR/sender_ext.cnf" "$CERTS_DIR/receiver_ext.cnf"

echo "Done. Files generated:"
echo "  runtime/certs/ca.crt       Root CA certificate"
echo "  runtime/certs/ca.key       Root CA private key"
echo "  runtime/certs/sender.crt   Sender certificate"
echo "  runtime/certs/sender.key   Sender private key"
echo "  runtime/certs/receiver.crt Receiver certificate"
echo "  runtime/certs/receiver.key Receiver private key"
