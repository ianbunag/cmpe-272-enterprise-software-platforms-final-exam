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

## Step 5 Run with Docker Compose

Docker Compose builds both binaries inside Alpine containers using multi-stage Dockerfiles
and places them on a private bridge network. The sender resolves the receiver by its
Docker service name which matches the DNS SAN baked into the receiver certificate.

Make sure Steps 1 and 2 are complete before running this step. The certs and the test
file must exist in runtime/ before the containers start.

Build both images.

```bash
cd approach-a-mtls
docker compose build
```

Start both containers in the background. They will stay alive until you stop them.

```bash
docker compose up -d
```

Open a shell inside the receiver container in one terminal.

```bash
docker compose exec receiver sh
```

Inside that shell start the receiver program.

```bash
./receiver \
  -addr  :9090 \
  -ca    /certs/ca.crt \
  -cert  /certs/receiver.crt \
  -key   /certs/receiver.key \
  -out   /output
```

The receiver prints the following and waits for a connection.

```
receiver listening on :9090
```

Open a second terminal and shell into the sender container.

```bash
docker compose exec sender sh
```

Inside that shell start the transfer.

```bash
./sender \
  -file        /data/test_4gb.bin \
  -addr        receiver:9090 \
  -ca          /certs/ca.crt \
  -cert        /certs/sender.crt \
  -key         /certs/sender.key \
  -server-name receiver
```

When the transfer completes both containers print their confirmation messages.

```
sender   | transfer complete
receiver | transfer complete. file saved to /output/test_4gb.bin sha256 verified
```

The received file lands in runtime/output/test_4gb.bin on your host machine.

To stop and remove the containers run the following command.

```bash
docker compose down
```

### Simulating a mid-transfer failure

To prove the fail-closed mechanism works open a third terminal and kill the sender
container while the transfer is running.

```bash
docker compose kill sender
```

The receiver detects the broken connection, logs an error, and deletes the partial
file. You can confirm runtime/output is empty after the kill.

### Verifying mutual authentication

To confirm the system rejects a connection without a valid certificate run the
following command from your host machine while the receiver is listening inside
the container.

```bash
openssl s_client -connect 127.0.0.1:9090
```

The receiver closes the connection immediately because no client certificate was
presented.

---

<!-- Step 6 and beyond will be added as each program is completed -->
