# Secure File Transfer

## Prerequisites

- OpenSSL
- Docker and Docker Compose

---

## Approach A — mTLS Streaming

### 1. Generate certificates

```bash
bash approach-a-mtls/gen_certs.sh
```

### 2. Generate the 4 GB test file

```bash
bash approach-a-mtls/gen_test_file.sh
```

### 3. Build the Docker images

```bash
cd approach-a-mtls
docker compose build
```

### 4. Start the containers

```bash
docker compose up -d
```

### 5. Start the receiver

In terminal 1:

```bash
docker compose exec receiver sh
```

```bash
./receiver -addr :9090 -ca /certs/ca.crt -cert /certs/receiver.crt -key /certs/receiver.key -out /output
```

### 6. Run the sender

In terminal 2:

```bash
docker compose exec sender sh
```

```bash
./sender -file /data/test_4gb.bin -addr receiver:9090 -ca /certs/ca.crt -cert /certs/sender.crt -key /certs/sender.key -server-name receiver
```

### 7. Verify

The receiver prints the following when the transfer is complete and the hash matches.

```
transfer complete. file saved to /output/test_4gb.bin sha256 verified
```

The received file is available on your host machine at `approach-a-mtls/runtime/output/test_4gb.bin`.

### 8. Tear down

```bash
docker compose down
```
