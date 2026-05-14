# Approach A Smoke Tests

## Test 1 Connection Cannot Be Established Until Receiver Is Ready

Verifies that the sender retries with exponential backoff when the receiver is not yet
listening and completes successfully once the receiver starts.

**Step 1.** Open a shell inside the sender container.

```bash
docker compose exec sender sh
```

**Step 2.** Start the sender. Because the receiver is not listening yet the sender will
begin retrying.

```bash
./sender -file /data/test_500mb.bin -addr receiver:9090 -ca /certs/ca.crt -cert /certs/sender.crt -key /certs/sender.key -server-name receiver
```

**Step 3.** Open a second terminal and start the receiver inside its container.

```bash
docker compose exec receiver sh
```

```bash
./receiver -addr :9090 -ca /certs/ca.crt -cert /certs/receiver.crt -key /certs/receiver.key -out /output
```

**Step 4.** The sender connects on its next retry attempt and the transfer completes.

**Step 5.** Confirm the received file exists and is intact on your host machine.

```bash
shasum -a 256 approach-a-mtls/runtime/output/test_500mb.bin approach-a-mtls/runtime/output/test_500mb.bin
ls -lh approach-a-mtls/runtime/output/test_500mb.bin
```

**Pass criteria.** Transfer completes and the file is present in runtime/output.

---

## Test 2 Connection Interrupted Mid-Transfer

Verifies that the receiver deletes the partial file and does not leave corrupt data on
disk when the sender disconnects before the transfer finishes.

**Step 1.** Ensure runtime/output is empty before starting.

```bash
ls approach-a-mtls/runtime/output/
```

**Step 2.** Start the receiver in terminal 1.

```bash
docker compose exec receiver sh
```

```bash
./receiver -addr :9090 -ca /certs/ca.crt -cert /certs/receiver.crt -key /certs/receiver.key -out /output
```

**Step 3.** Start the sender in terminal 2.

```bash
docker compose exec sender sh
```

```bash
./sender -file /data/test_500mb.bin -addr receiver:9090 -ca /certs/ca.crt -cert /certs/sender.crt -key /certs/sender.key -server-name receiver
```

**Step 4.** Once you see progress logs from the sender open a third terminal and kill
the sender container.

```bash
docker compose kill sender
```

**Step 5.** The receiver detects the broken connection and removes the partial file.

**Step 6.** Confirm no file was left behind on your host machine.

```bash
ls approach-a-mtls/runtime/output/
```

**Pass criteria.** The output directory is empty. No `.tmp` file and no final file remain.

---

## Test 3 Attacker Tries to Connect With an Untrusted Certificate

Verifies that the receiver rejects any TLS connection that does not present a certificate
signed by the trusted Root CA.

**Step 1.** Start the receiver in terminal 1.

```bash
docker compose exec receiver sh
```

```bash
./receiver -addr :9090 -ca /certs/ca.crt -cert /certs/receiver.crt -key /certs/receiver.key -out /output
```

**Step 2.** Open a shell inside the attacker container in terminal 2.

```bash
docker compose exec attacker sh
```

**Step 3.** Generate a self-signed certificate inside the attacker container. This cert
is not signed by the Root CA.

```bash
openssl req -x509 -newkey rsa:2048 -keyout /tmp/fake.key -out /tmp/fake.crt -days 1 -nodes -subj "/CN=attacker"
```

**Step 4.** Attempt a connection to the receiver using the fake certificate.

```bash
openssl s_client -connect receiver:9090 -cert /tmp/fake.crt -key /tmp/fake.key
```

**Step 6.** Confirm the receiver logged the rejected connection but wrote nothing to disk.

**Step 7.** Confirm runtime/output is still empty on your host machine.

```bash
ls approach-a-mtls/runtime/output/
```

**Pass criteria.** Both connection attempts are rejected. The output directory remains empty.

---

## Teardown

Stop and remove all containers after testing.

```bash
docker compose down
```

To reset runtime/output between tests run the following command.

```bash
rm -f approach-a-mtls/runtime/output/*
```
