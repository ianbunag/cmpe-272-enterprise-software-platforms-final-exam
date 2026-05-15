# Approach B Design — Hybrid RSA-AES Envelope over Plain TCP

---

## Architecture

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                       Docker: transfer-net                       │
  │                                                                  │
  │  ┌───────────────┐    Plain TCP :9000     ┌───────────────────┐  │
  │  │    sender     │ ─────────────────────> │    receiver       │  │
  │  │               │  1. RSA-OAEP envelope  │                   │  │
  │  │  hash file    │  2. RSA-PSS signature  │  verify PSS sig   │  │
  │  │  gen AES key  │  3. AES-GCM header     │  decrypt header   │  │
  │  │  sign env     │  4. <── resume index   │  load state file  │  │
  │  │  send chunks  │  5. AES-GCM chunks     │  seek to offset   │  │
  │  │  retry loop   │                        │  verify AEAD tags │  │
  │  └───────────────┘                        │  write .tmp       │  │
  │                                           │  sha256 verify    │  │
  │  ┌───────────────┐                        │  rename to final  │  │
  │  │   attacker    │  (no sender private    └───────────────────┘  │
  │  │  nc receiver  │   key — sig fails)                            │
  │  │    9000       │ ──────────────────────────────────────── X    │
  │  └───────────────┘                                               │
  └──────────────────────────────────────────────────────────────────┘

  Host volumes
  ┌──────────────────────────────────────────────────────────────────┐
  │  runtime/keys/     →  /keys      (read-only, sender + receiver)  │
  │  runtime/data/     →  /data      (read-only, sender only)        │
  │  runtime/output/   →  /output    (writable, receiver only)       │
  │  runtime/sessions/ →  /sessions  (writable, sender only)         │
  └──────────────────────────────────────────────────────────────────┘
```

---

## Wire Protocol

Every frame is length-prefixed with a 4-byte big-endian uint32 followed by that many bytes.
The resume index is a single 8-byte big-endian uint64 sent by the receiver with no length prefix.

```
Sender                                          Receiver
  │                                                │
  │── [4B len][RSA-OAEP ciphertext] ──────────────>│  decrypt with receiver private key
  │── [4B len][RSA-PSS signature] ─────────────────>│  verify with sender public key
  │── [4B len][12B nonce + AES-GCM header] ────────>│  decrypt session info JSON
  │<─ [8B resume chunk index] ──────────────────────│  0 for fresh start, N for resume
  │                                                │
  │── [4B len][AES-GCM chunk 0] ───────────────────>│  nonce derived from index 0
  │── [4B len][AES-GCM chunk 1] ───────────────────>│  nonce derived from index 1
  │   ...                                          │
  │── [4B len][AES-GCM chunk N-1] ─────────────────>│  nonce derived from index N-1
```

The RSA-OAEP ciphertext carries `aes_key[32] || session_id[16]` (48 bytes plaintext).
The RSA-PSS signature covers `SHA-256(rsa_ciphertext_bytes)`.
The session info JSON carries filename, file size, total chunks, chunk size, and expected SHA-256.

---

## Key Exchange and Key Management

### Pre-distributed Keys

Both parties generate their RSA key pairs offline via `generate_keys.sh`. The receiver keeps
`receiver_private.pem` and is given `sender_public.pem`. The sender keeps
`sender_private.pem` and is given `receiver_public.pem`. No private key ever leaves its
owner's container and no key material is baked into any Docker image.

| Party    | Key type | Key size | Role |
|----------|----------|----------|------|
| Receiver | RSA      | 4096 bit | Private key decrypts the session envelope. Public key distributed to sender. |
| Sender   | RSA      | 4096 bit | Private key signs the session envelope. Public key distributed to receiver. |

### Per-connection AES Session Key

On each TCP connection the sender generates a fresh 32-byte AES key using `crypto/rand`.
This key is encrypted under the receiver's public key via RSA-OAEP and is only valid for
that connection segment. A captured segment's ciphertext cannot be decrypted using the AES key
from any other segment because every connection generates an independent key. This provides
per-connection forward secrecy without requiring an interactive Diffie-Hellman exchange.

### Session Identity for Resumability

A 16-byte random session ID is generated on the first connection and persisted to
`/sessions/<filename>.session` on the sender side. On reconnect the sender reuses the same
session ID so the receiver can match the new connection to the prior partial transfer. The
session ID is always transmitted inside the RSA-OAEP ciphertext and therefore never exposed
in plaintext on the wire.

---

## Chunking and Framing

### Chunk Size

The sender reads the file in 1 MB chunks. This size was chosen to balance memory usage
against system call overhead and to make resumability granular enough that a killed transfer
does not lose more than 1 MB of progress.

### Nonce Derivation

The AES-GCM nonce for chunk `i` is a 12-byte value where bytes 0 through 3 are zero and
bytes 4 through 11 hold `i` encoded as a big-endian uint64. This derivation is deterministic
on both sides so the nonce is never transmitted for data chunks. The header uses a random
12-byte nonce generated per connection which is prepended to the ciphertext frame and
therefore does appear on the wire.

Since every connection generates a new AES key no (key, nonce) pair is ever reused across
connections. Within a single connection each chunk index is unique so no (key, nonce) pair
is ever reused within a connection either.

### Resumption

The receiver persists a JSON state file to `/output/<session_id_hex>.state` after each
verified chunk. The state records the session ID hex, filename, total chunks, chunk size,
chunks verified, and expected SHA-256. On reconnect the receiver reads this file to determine
the resume chunk index and seeks the temp file write pointer to `resume_chunk * chunk_size`
before accepting new chunks.

---

## Algorithms and Parameters

| Property            | Algorithm or Parameter                                         |
|---------------------|----------------------------------------------------------------|
| Key exchange        | RSA-OAEP with SHA-256 (no interactive handshake)              |
| Session key size    | AES-256 (32 bytes, generated fresh per connection)            |
| Sender auth         | RSA-PSS with SHA-256 over SHA-256(rsa_ciphertext)             |
| Symmetric cipher    | AES-256-GCM (crypto/cipher)                                   |
| AEAD tag size       | 16 bytes                                                      |
| Chunk nonce         | 12 bytes, bytes 4-11 = big-endian uint64 chunk index          |
| Header nonce        | 12 bytes, crypto/rand per connection                          |
| File integrity      | SHA-256 end-to-end over full plaintext (crypto/sha256)        |
| RSA key size        | 4096 bits                                                     |
| Chunk size          | 1 MB (1,048,576 bytes)                                        |

---

## Threat Model

| Threat | CIAA bucket | Mechanism in this design |
|--------|-------------|--------------------------|
| Passive eavesdropper records the entire TCP stream | Confidentiality | The AES session key is encrypted under the receiver's RSA public key and never appears in plaintext on the wire. Every file byte is encrypted with AES-256-GCM before leaving the sender. An eavesdropper sees only ciphertext and an RSA-OAEP blob from which the session key cannot be recovered without the receiver's private key. |
| Active man-in-the-middle modifies bytes mid-flight | Integrity | Each chunk carries a 16-byte AES-GCM authentication tag. Any modification to the ciphertext causes `gcm.Open` to return an error and the receiver immediately drops the connection and removes the partial file. The end-to-end SHA-256 comparison over the full decrypted plaintext provides a second independent integrity check at the file level. |
| Attacker spoofs the sender or the receiver | Authenticity | The receiver verifies the RSA-PSS signature over the RSA-OAEP ciphertext using the known sender public key before decrypting any session data or accepting any chunks. An attacker without the sender's private key cannot produce a valid signature and the receiver closes the connection at that step. The sender encrypts the session key under the known receiver public key so only the correct receiver can unwrap it and proceed. |
| Replay of an earlier valid transfer | Integrity and Authenticity | Each connection uses a freshly generated AES key so a replay of a captured segment's ciphertext stream fails AEAD verification under the new connection's key. Additionally the resume handshake is bidirectional. After decrypting the header the receiver sends a resume index to the sender. A replayer injecting a recorded stream cannot respond to this message so the bidirectional protocol cannot be completed by passive replay. |
| Connection drops at 80% transferred | Availability | The receiver writes each verified chunk to a `.tmp` file and persists a `.state` file after every chunk. On reconnect the receiver reads the state file and sends a non-zero resume index. The sender seeks to the corresponding file offset and continues from that point. The fail-closed defer ensures the `.tmp` file is removed if the final SHA-256 check fails so no partial file is ever left under the final filename. |
| Untrusted intermediary (broker or object store) | Confidentiality and Integrity | Encryption happens at the application layer on the sender before any bytes enter the TCP stream. A broker or storage tier that receives or caches the stream sees only AES-256-GCM ciphertext. Without the AES session key the broker cannot read or silently modify the file contents. Any modification to the ciphertext invalidates the per-chunk AEAD tags and is detected by the receiver before the data reaches disk. |
