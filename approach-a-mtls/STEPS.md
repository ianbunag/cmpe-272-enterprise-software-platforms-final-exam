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
The script lives in the certs directory and writes all generated files into runtime/certs.
Run it once before doing anything else.

```bash
bash approach-a-mtls/gen_certs.sh
```

To confirm the certificates are valid run the following two commands.
Each one should print OK.

```bash
openssl verify -CAfile approach-a-mtls/runtime/certs/ca.crt approach-a-mtls/runtime/certs/sender.crt
openssl verify -CAfile approach-a-mtls/runtime/certs/ca.crt approach-a-mtls/runtime/certs/receiver.crt
```

---

## Step 2 Generate the Test File

Run this script once before starting the containers. It creates a 4 GB file of random
bytes in runtime/data which is mounted into the sender container. If the file already
exists the script exits without regenerating it.

```bash
bash approach-a-mtls/gen_test_file.sh
```

The script prints the file path and size when done.

```
Generating 4 GB test file at approach-a-mtls/runtime/data/test_4gb.bin
Done. File size: 4.0G
```

All runtime files live under runtime/ which is gitignored so nothing generated at
runtime is ever committed to the repository.

---

## Step 3 Start the Receiver

The receiver listens for an incoming mTLS connection, streams the file to disk in 32 KB
chunks, verifies the SHA-256 hash, and only saves the file once the full transfer is confirmed.
If anything goes wrong the partial file is deleted automatically.

Build the receiver binary from the module root.

```bash
cd approach-a-mtls
go build -o runtime/bin/receiver ./cmd/receiver/
```

Run the receiver with the paths to its certificate, its private key, and the shared Root CA.

```bash
./runtime/bin/receiver \
  -addr  :9090 \
  -ca    runtime/certs/ca.crt \
  -cert  runtime/certs/receiver.crt \
  -key   runtime/certs/receiver.key \
  -out   runtime/output
```

The receiver will print a confirmation and wait for a connection.

```
receiver listening on :9090
```

Once a transfer completes successfully it prints the following.

```
transfer complete. file saved to runtime/output/<filename> sha256 verified
```

If the connection drops or the hash does not match it prints a failure message and
removes the partial file from disk.

---

## Step 4 Run the Sender

The sender computes a SHA-256 hash of the file before transfer, connects to the receiver
over mTLS, sends a JSON header with the filename and hash, then streams the file in 32 KB
chunks. It prints throughput and progress every 100 MB and retries the connection up to
five times with exponential backoff if the receiver is not yet ready.

Build the sender binary from the module root.

```bash
cd approach-a-mtls
go build -o runtime/bin/sender ./cmd/sender/
```

Run the sender pointing at the file you want to transfer and the receiver address.

```bash
./runtime/bin/sender \
  -file        runtime/data/test_4gb.bin \
  -addr        receiver:9090 \
  -ca          runtime/certs/ca.crt \
  -cert        runtime/certs/sender.crt \
  -key         runtime/certs/sender.key \
  -server-name receiver
```

The sender prints the hash it computed, progress every 100 MB, a throughput summary,
and a final confirmation when the transfer completes.

```
computing SHA-256 hash of runtime/data/test_4gb.bin
file size 4294967296 bytes hash <sha256>
connected to receiver:9090
progress 2.4% sent 100 MB throughput 312.50 MB/s
...
sent 4294967296 bytes (4096.0 MB) in 13.1 seconds average 312.67 MB/s
transfer complete
```

The receiver confirms the hash matches and saves the file.

```
transfer complete. file saved to runtime/output/test_4gb.bin sha256 verified
```

---

<!-- Step 5 and beyond will be added as each program is completed -->
