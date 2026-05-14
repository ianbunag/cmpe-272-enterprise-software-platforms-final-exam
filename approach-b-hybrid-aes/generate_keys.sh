#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/runtime/keys"

echo "Generating RSA 4096-bit key pairs in $KEYS_DIR"

# Receiver key pair
# The receiver private key is used to decrypt the AES session key sent by the sender.
# The receiver public key is distributed to the sender before any transfer begins.
openssl genrsa -out "$KEYS_DIR/receiver_private.pem" 4096

openssl rsa -in "$KEYS_DIR/receiver_private.pem" \
  -pubout -out "$KEYS_DIR/receiver_public.pem"

# Sender key pair
# The sender private key is used to sign the session header for mutual authentication.
# The receiver verifies this signature using the sender public key before accepting any data.
# This ensures the receiver can confirm the sender's identity and not just the sender's
# knowledge of the receiver's public key.
openssl genrsa -out "$KEYS_DIR/sender_private.pem" 4096

openssl rsa -in "$KEYS_DIR/sender_private.pem" \
  -pubout -out "$KEYS_DIR/sender_public.pem"

chmod 600 "$KEYS_DIR/receiver_private.pem" "$KEYS_DIR/sender_private.pem"
chmod 644 "$KEYS_DIR/receiver_public.pem"  "$KEYS_DIR/sender_public.pem"

echo "Done. Files generated:"
echo "  runtime/keys/receiver_private.pem   Receiver RSA private key (kept on receiver only)"
echo "  runtime/keys/receiver_public.pem    Receiver RSA public key (distributed to sender)"
echo "  runtime/keys/sender_private.pem     Sender RSA private key (kept on sender only)"
echo "  runtime/keys/sender_public.pem      Sender RSA public key (distributed to receiver)"
