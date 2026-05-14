# Approach A Usage Guide

This guide explains how to run the mTLS secure file transfer programs from start to finish.

---

## Prerequisites

You need the following tools installed before running anything.

- OpenSSL
- Go 1.21 or later
- Docker and Docker Compose

---

## Step 1 Generate Certificates

Both the sender and the receiver must present certificates signed by a shared Root CA.
Run the generation script once before doing anything else.

```bash
bash approach-a-mtls/certs/gen_certs.sh
```

To confirm the certificates are valid run the following two commands.
Each one should print OK.

```bash
openssl verify -CAfile approach-a-mtls/certs/ca.crt approach-a-mtls/certs/sender.crt
openssl verify -CAfile approach-a-mtls/certs/ca.crt approach-a-mtls/certs/receiver.crt
```

---

## Step 2 Start the Receiver

The receiver listens for an incoming mTLS connection, streams the file to disk in 32 KB
chunks, verifies the SHA-256 hash, and only saves the file once the full transfer is confirmed.
If anything goes wrong the partial file is deleted automatically.

Build the receiver binary from the module root.

```bash
cd approach-a-mtls
go build -o receiver ./cmd/receiver/
```

Run the receiver with the paths to its certificate, its private key, and the shared Root CA.

```bash
./receiver \
  -addr  :9090 \
  -ca    certs/ca.crt \
  -cert  certs/receiver.crt \
  -key   certs/receiver.key \
  -out   ./output
```

The receiver will print a confirmation and wait for a connection.

```
receiver listening on :9090
```

Once a transfer completes successfully it prints the following.

```
transfer complete. file saved to ./output/<filename> sha256 verified
```

If the connection drops or the hash does not match it prints a failure message and
removes the partial file from disk.

---

<!-- Step 3 and beyond will be added as each program is completed -->
