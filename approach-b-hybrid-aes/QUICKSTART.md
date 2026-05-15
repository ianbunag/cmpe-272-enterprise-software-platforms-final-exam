# Approach B Quick Start — Hybrid RSA-AES Envelope

## Prerequisites

- OpenSSL
- Docker and Docker Compose

---

### 1. Generate RSA key pairs

```bash
bash generate_keys.sh
```

### 2. Generate test files

```bash
bash gen_test_file.sh
```

### 3. Build the Docker images

```bash
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
./receiver -addr :9000 -key /keys/receiver_private.pem -sender-pub /keys/sender_public.pem -out /output
```

### 6. Run the sender

In terminal 2:

```bash
docker compose exec sender sh
```

```bash
./sender -file /data/test_4gb.bin -addr receiver:9000 -receiver-pub /keys/receiver_public.pem -key /keys/sender_private.pem -session-dir /sessions
```

### 7. Verify

The receiver prints the following when the transfer is complete and the hash matches.

```
transfer complete received ... file saved to /output/test_4gb.bin sha256 verified
```

The received file is available on your host machine at `runtime/output/test_4gb.bin`.

### 8. Tear down

```bash
docker compose down
```
