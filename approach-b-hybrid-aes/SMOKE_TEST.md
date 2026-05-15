# Approach B Smoke Tests

## Test 1 Storage Corruption Detected by End-to-End SHA-256

Verifies that the receiver catches a corrupted byte in the temp file during finalization
and refuses to produce the final output file. Per-chunk AEAD tags protect bytes in flight
but a byte flipped directly on disk after a chunk lands is only caught by the end-to-end
SHA-256 comparison. This test exercises that second layer of integrity.

**Step 1.** Build and start the containers.

```bash
docker compose build
docker compose up -d
```

**Step 2.** Start the receiver in terminal 1.

```bash
docker compose exec receiver sh
```

```bash
./receiver -addr :9000 -key /keys/receiver_private.pem -sender-pub /keys/sender_public.pem -out /output
```

**Step 3.** Start the sender in terminal 2.

```bash
docker compose exec sender sh
```

```bash
./sender -file /data/test_500mb.bin -addr receiver:9000 -receiver-pub /keys/receiver_public.pem -key /keys/sender_private.pem -session-dir /sessions
```

**Step 4.** Once you see a few progress lines from the receiver kill the sender.

```bash
docker compose kill sender
```

**Step 5.** Find the `.tmp` file in the output directory on your host machine and flip one
byte at offset 1000 to simulate storage corruption of an already-written chunk.

```bash
python3 -c "
f = open('approach-b-hybrid-aes/runtime/output/$(ls approach-b-hybrid-aes/runtime/output/ | grep .tmp | head -1)', 'r+b')
f.seek(1000)
f.write(b'X')
f.close()
"
```

**Step 6.** Restart the sender container and resume the transfer.

```bash
docker compose start sender
docker compose exec sender sh
```

```bash
./sender -file /data/test_500mb.bin -addr receiver:9000 -receiver-pub /keys/receiver_public.pem -key /keys/sender_private.pem -session-dir /sessions
```

**Step 7.** The transfer resumes and completes all remaining chunks. When the receiver
reaches the final SHA-256 check it will log a mismatch and remove the temp file.

**Step 8.** Confirm no output file was produced.

```bash
ls approach-b-hybrid-aes/runtime/output/
```

**Pass criteria.** The receiver logs a SHA-256 mismatch and removes the `.tmp` file.
No final output file exists. The per-chunk AEAD tags passed because the corruption happened
on disk after decryption, proving that the end-to-end hash is the mechanism that caught it.

---

## Test 2 Mid-Transfer Interruption and Resumption

Verifies that the receiver retains the partial file and state when the sender is killed
and that the transfer continues from the last verified chunk when the sender reconnects.

**Step 1.** Ensure the output directory is clean before starting.

```bash
ls approach-b-hybrid-aes/runtime/output/
ls approach-b-hybrid-aes/runtime/sessions/
```

**Step 2.** Start the receiver in terminal 1.

```bash
docker compose exec receiver sh
```

```bash
./receiver -addr :9000 -key /keys/receiver_private.pem -sender-pub /keys/sender_public.pem -out /output
```

**Step 3.** Start the sender in terminal 2.

```bash
docker compose exec sender sh
```

```bash
./sender -file /data/test_500mb.bin -addr receiver:9000 -receiver-pub /keys/receiver_public.pem -key /keys/sender_private.pem -session-dir /sessions
```

**Step 4.** Once you see progress logs from the receiver open a third terminal and kill
the sender container.

```bash
docker compose kill sender
```

**Step 5.** Confirm the receiver kept the partial state and did not write the final file.

```bash
ls approach-b-hybrid-aes/runtime/output/
```

You should see a `.tmp` file and a `.state` file but no final `test_500mb.bin`.

**Step 6.** Restart the sender container and reconnect.

```bash
docker compose start sender
docker compose exec sender sh
```

```bash
./sender -file /data/test_500mb.bin -addr receiver:9000 -receiver-pub /keys/receiver_public.pem -key /keys/sender_private.pem -session-dir /sessions
```

**Step 7.** Observe that the receiver logs a non-zero resume chunk index such as
`resuming session ... from chunk 150 of 512` instead of starting from zero.

**Step 8.** After completion verify the hashes on your host machine.

```bash
shasum -a 256 approach-b-hybrid-aes/runtime/data/test_500mb.bin approach-b-hybrid-aes/runtime/output/test_500mb.bin
```

**Pass criteria.** The receiver resumes from a non-zero chunk. The final file hash matches
the source. No `.tmp` or `.state` files remain after completion.

---

## Test 3 Attacker Connects Without Valid Credentials

Verifies that the receiver rejects any connection where the sender cannot produce a valid
RSA-PSS signature over the session envelope. The attacker can reach the TCP port but has
no access to the sender private key.

**Step 1.** Start the receiver in terminal 1.

```bash
docker compose exec receiver sh
```

```bash
./receiver -addr :9000 -key /keys/receiver_private.pem -sender-pub /keys/sender_public.pem -out /output
```

**Step 2.** Open a shell in the attacker container in terminal 2.

```bash
docker compose exec attacker sh
```

**Step 3.** Generate a fake session envelope with random bytes and encrypt it with the receiver's public key to simulate an attacker who can reach the TCP port but has no access to the sender private key.

```bash
head -c 48 /dev/urandom > fake_envelope.bin
openssl pkeyutl -encrypt -pubin -inkey /keys/receiver_public.pem -in fake_envelope.bin -out forged_rsa.bin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256
```

**Step 4.** Send raw bytes to the receiver TCP port to simulate a spoofed connection.

```bash
(printf "\x00\x00\x02\x00"; cat forged_rsa.bin; printf "\x00\x00\x02\x00"; head -c 512 /dev/urandom) | nc receiver 9000
```

**Step 5.** Confirm the receiver logged a frame or decrypt error and closed the connection.

**Step 6.** Confirm nothing was written to disk.

```bash
ls approach-b-hybrid-aes/runtime/output/
```

**Pass criteria.** The receiver rejects the connection and the output directory remains empty.

---

## Teardown

```bash
docker compose down
```

To reset runtime directories between tests run the following.

```bash
rm -f approach-b-hybrid-aes/runtime/output/*
rm -f approach-b-hybrid-aes/runtime/sessions/*
```
