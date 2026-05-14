# Approach A Design — mTLS Streaming over TCP

---

## Architecture

```
  ┌─────────────────────────────────────────────────────────────┐
  │                     Docker: transfer-net                    │
  │                                                             │
  │  ┌──────────────┐   TLS 1.3 / TCP :9090   ┌─────────────┐  │
  │  │    sender    │ ──────────────────────> │   receiver  │  │
  │  │              │   1. JSON header        │             │  │
  │  │  hash file   │   2. raw file stream    │  write .tmp │  │
  │  │  send header │                         │  hash bytes │  │
  │  │  stream file │                         │  verify     │  │
  │  │  log progress│                         │  rename     │  │
  │  └──────────────┘                         └─────────────┘  │
  │                                                             │
  │  ┌──────────────┐                                           │
  │  │   attacker   │  (no valid cert — handshake rejected)     │
  │  │   openssl    │ ─────────────────────────────────────X    │
  │  └──────────────┘                                           │
  └─────────────────────────────────────────────────────────────┘

  Host volumes
  ┌─────────────────────────────────────────────────────────────┐
  │  runtime/certs/  →  /certs  (read-only, sender + receiver)  │
  │  runtime/data/   →  /data   (read-only, sender only)        │
  │  runtime/output/ →  /output (writable, receiver only)       │
  └─────────────────────────────────────────────────────────────┘
```

---

## Key Exchange and Key Management

### Handshake

TLS 1.3 performs an ephemeral Diffie-Hellman key exchange (ECDHE) on every new connection.
Go's `crypto/tls` selects X25519 as the preferred key exchange group. The shared secret is
used to derive per-session symmetric keys via HKDF. No long-lived secret material is
ever transmitted on the wire.

### Long-lived Keys

| Party    | Key type | Key size | Validity |
|----------|----------|----------|----------|
| Root CA  | RSA      | 4096 bit | 10 years |
| Sender   | RSA      | 4096 bit | 365 days |
| Receiver | RSA      | 4096 bit | 365 days |

All certificates are X.509 v3. The sender and receiver certificates are signed by the
Root CA. The Root CA certificate is self-signed.

### Certificate Distribution

Certificates are generated offline by `gen_certs.sh` using OpenSSL and written to
`runtime/certs/`. They are mounted into containers as read-only volumes. No key
material is baked into any Docker image or committed to the repository.

### Certificate Extensions

| Certificate | Extended Key Usage | Subject Alternative Name |
|-------------|-------------------|--------------------------|
| Sender      | clientAuth        | none required            |
| Receiver    | serverAuth        | DNS:receiver, IP:127.0.0.1 |

The receiver SAN covers both Docker service-name resolution and loopback testing.

---

## Chunking and Framing

### Pre-transfer Header

Before any file data is sent the sender writes a single newline-terminated JSON object
to the TLS connection.

```json
{"filename":"test_4gb.bin","expected_sha256":"<hex>","file_size":4294967296}
```

The receiver reads this line with `bufio.Reader.ReadString('\n')`, parses it, and uses
the values to name the output file and to compare the final hash. The same `bufio.Reader`
is then used to stream the remaining bytes so no data is lost at the boundary.

### Data Stream

After the header the sender writes the raw file bytes with no additional framing. The
stream is terminated by the TCP connection close after the last byte is flushed.

The receiver does not treat the TCP FIN as proof of completeness. It verifies both the
byte count and the SHA-256 hash before accepting the file.

### Chunk Size

Both programs use a fixed 32 KB (32,768 byte) buffer. This value was chosen to keep
memory usage low while avoiding excessive system call overhead. A single 32 KB read
spans at most two TLS records (TLS maximum record size is 16 KB).

---

## Algorithms and Parameters

| Property          | Algorithm / Parameter                              |
|-------------------|----------------------------------------------------|
| TLS version       | TLS 1.3 (enforced via `MinVersion: tls.VersionTLS13`) |
| Key exchange      | ECDHE with X25519 (Go default for TLS 1.3)        |
| Symmetric cipher  | AES-256-GCM or ChaCha20-Poly1305 (negotiated)     |
| AEAD tag size     | 16 bytes                                           |
| Key derivation    | HKDF (built into TLS 1.3 record layer)            |
| File integrity    | SHA-256 (crypto/sha256)                            |
| Certificate sig   | RSA with SHA-256 (sha256WithRSAEncryption)         |
| RSA key size      | 4096 bits                                          |
| Chunk size        | 32 KB                                              |

---

## Threat Model

| Threat | CIAA bucket | Mechanism in this design |
|--------|-------------|--------------------------|
| Passive eavesdropper records the entire TCP stream | Confidentiality | TLS 1.3 ECDHE derives a per-session key that never appears on the wire. All file bytes are encrypted under AES-256-GCM or ChaCha20-Poly1305 before leaving the sender. |
| Active man-in-the-middle modifies bytes mid-flight | Integrity | Each TLS record carries a 16-byte AEAD authentication tag. Any modification causes a fatal TLS alert and aborts the connection. The end-to-end SHA-256 comparison provides a second independent check at the file level. |
| Attacker spoofs the sender or the receiver | Authenticity | The receiver sets `RequireAndVerifyClientCert` and verifies the client certificate against the Root CA pool. The sender verifies the receiver's certificate against the same pool and checks the ServerName against the receiver's SAN. A certificate not signed by the Root CA fails verification and the handshake is aborted. |
| Replay of an earlier valid transfer | Integrity / Authenticity | TLS 1.3 derives fresh session keys from a new ECDHE exchange on every connection. A captured ciphertext stream cannot be decrypted under new session keys. Re-presenting a captured stream requires re-establishing a handshake, which requires valid long-lived credentials. |
| Connection drops at 80% transferred | Availability | The receiver wraps the entire transfer in a `defer` that calls `os.Remove()` on the `.tmp` file unless a `success` flag is set. Any read error, size mismatch, or hash mismatch leaves the flag unset and the partial file is deleted. The final filename is only written after `os.Rename()` succeeds on a fully verified file. |
| Untrusted intermediary (broker / object store) | Confidentiality / Integrity | Not applicable. This approach streams directly from sender to receiver over a single TLS connection. There is no broker, relay, or object store in the data path. |
