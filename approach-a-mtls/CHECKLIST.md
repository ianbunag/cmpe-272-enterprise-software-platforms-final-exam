# Approach A Checklist

---

## Why Go?

Go's standard library includes `crypto/tls` with first-class TLS 1.3 support and `crypto/x509`
for certificate management, so no third-party crypto dependencies are needed. Its
`io.Reader` and `io.Writer` interfaces make streaming I/O idiomatic and correct by default.
Building with `CGO_ENABLED=0` produces a single statically linked binary that runs inside a
minimal Alpine Docker image with no runtime dependencies. Go's goroutine model also makes it
straightforward to handle each incoming connection concurrently on the receiver without blocking.

---

## How Does the Program Handle 4 GB Files Not Fitting Into Memory?

Both programs use a fixed 32 KB buffer throughout the entire transfer. The sender opens the
source file and reads it in 32 KB chunks, writing each chunk directly to the TLS connection.
The receiver reads from the TLS connection in 32 KB chunks using `bufio.NewReaderSize` and
writes each chunk simultaneously to disk and to a running SHA-256 hasher via `io.MultiWriter`.
At no point is more than one chunk held in memory. Total memory usage is constant regardless
of file size.

---

## How Does the Program Handle Transfer Interrupts?

The implementation uses a fail-safe approach rather than resumability.

The receiver opens a `.tmp` file for writing and registers a `defer` block before any data is
read. The defer checks a `success` flag and calls `os.Remove()` on the `.tmp` path if the
flag was never set to true. Any failure — network drop, read error, size mismatch, or hash
mismatch — causes the function to return without setting the flag, which triggers the cleanup.

The final filename is only written after `os.Rename()` succeeds on a file that has passed
both the size check and the SHA-256 comparison. There is no code path that leaves a partial
file behind under the final name.

To simulate an interrupt, `docker compose kill sender` is used mid-transfer. This is
documented in SMOKE_TEST.md Test 2.

---

## How Does the Program Conform to the CIAA Framework?

### Confidentiality

TLS 1.3 encrypts every byte of the file stream using AEAD cipher suites. Go's `crypto/tls`
negotiates either AES-256-GCM or ChaCha20-Poly1305 automatically. The session key is derived
from an ephemeral Diffie-Hellman exchange and never appears on the wire in plaintext. An
eavesdropper recording the TCP stream sees only ciphertext.

### Integrity

The sender computes a SHA-256 hash of the entire source file before the transfer begins and
includes it in a JSON header sent before the data stream. The receiver recomputes the hash
incrementally as each chunk arrives using `io.MultiWriter`. After the stream ends the two
hashes are compared. A mismatch aborts the transfer and deletes the partial file. The TLS
record-layer AEAD tags also protect each individual record in transit as a first line of
defence against in-flight modification.

### Authenticity

Both parties present X.509 certificates signed by a shared Root CA. The receiver is configured
with `ClientAuth: tls.RequireAndVerifyClientCert` and a `ClientCAs` pool containing only the
Root CA. The sender presents its certificate and verifies the receiver's certificate against
the same Root CA using a `RootCAs` pool. `MinVersion: tls.VersionTLS13` prevents any downgrade
to weaker TLS versions. A connection from any party that cannot present a CA-signed certificate
is rejected at the handshake.

### Availability

TCP's built-in retransmission handles packet loss transparently. The sender retries connection
attempts up to five times with exponential backoff starting at one second and capped at thirty
seconds. The fail-safe design ensures a failed transfer leaves the filesystem in a clean state
so a fresh retry can begin immediately without manual intervention.

---

## How Are Each of the Threat Models Addressed?

### Passive Eavesdropper Recording the Entire TCP Stream

TLS 1.3 encrypts the entire stream before it leaves the sender. All file bytes appear as
ciphertext on the wire. The session key is ephemeral and never transmitted so recording the
full stream yields nothing usable without the private keys from both parties.

### Active Man-in-the-Middle Modifies Bytes Mid-Flight

The TLS AEAD tag covers each record. Any byte modification in transit causes the TLS layer to
raise a fatal alert and abort the connection before corrupted data reaches the application.
The end-to-end SHA-256 comparison provides a second independent layer of integrity verification
at the file level.

### Attacker Spoofs the Sender or the Receiver

Both parties verify each other's certificates against the trusted Root CA pool. An attacker
without a private key corresponding to a CA-signed certificate cannot complete the TLS
handshake. The receiver logs the rejection and writes nothing to disk. This is demonstrated
in SMOKE_TEST.md Test 3 using the attacker Docker container.

### Replay of an Earlier Valid Transfer

TLS 1.3 generates fresh ephemeral keys for every session via ECDHE. A replayed captured stream
cannot be decrypted with the new session keys. Replaying requires re-establishing a new
handshake, which requires valid credentials the attacker does not possess.

### Connection Drops at 80% Transferred

The receiver detects the broken connection via a read error on the stream. The `defer` block
fires, `os.Remove()` deletes the `.tmp` file, and the receiver logs the cleanup. No partial
file remains on disk under any name. The receiver immediately returns to its accept loop and
is ready for a new connection. This is demonstrated in SMOKE_TEST.md Test 2.

### Untrusted Intermediary (Broker / Object Store), if Used

Not applicable. This approach uses a direct sender-to-receiver TLS stream with no intermediary.
There is no broker, object store, or relay node in the data path.

---

## How Does the Program Verify That the Exact File Is Received?

The sender streams the source file through a SHA-256 hasher before the transfer and includes
the hex-encoded digest in the JSON header it sends first. The receiver passes every incoming
byte through `io.MultiWriter`, which writes simultaneously to disk and to a running SHA-256
hasher. After the stream closes the receiver encodes its computed digest and compares it
character-by-character with the expected digest from the header. If they do not match the
transfer is aborted and the partial file is deleted.

---

## How Does the Program Verify the Identity of the Sender and Receiver?

Mutual TLS is used. The receiver configures `ClientAuth: tls.RequireAndVerifyClientCert` so
every incoming connection must present a certificate. Both parties load the Root CA into a
certificate pool and reject any peer whose certificate does not chain back to that CA. The
sender sets `ServerName: "receiver"` which is verified against the Subject Alternative Name
in the receiver's certificate. TLS 1.3 is enforced via `MinVersion: tls.VersionTLS13` so
there is no fallback to weaker protocol versions.

---

## Does the Program Use Authenticated Encryption (AEAD)?

Yes. TLS 1.3 mandates AEAD cipher suites and prohibits unauthenticated modes entirely. Go's
`crypto/tls` automatically negotiates AES-256-GCM or ChaCha20-Poly1305 depending on hardware
capability. There is no use of CBC, CTR, or any cipher mode that does not provide authentication.

---

## Which Existing Crypto Libraries Are Used?

All cryptography comes from the Go standard library. No third-party packages are used.

| Package | Purpose |
|---|---|
| `crypto/tls` | TLS 1.3 connection, mutual authentication, AEAD encryption of the stream |
| `crypto/x509` | Loading and verifying X.509 certificates against the Root CA pool |
| `crypto/sha256` | Computing the end-to-end integrity hash of the file |
| `encoding/hex` | Encoding and comparing the SHA-256 digest as a hex string |
