# Approach B Checklist

---

## Why Go?

Go's standard library provides `crypto/aes`, `crypto/cipher`, `crypto/rsa`, and `crypto/rand`
so no third-party crypto dependencies are needed. Its `io.Reader` and `io.Writer` interfaces
make streaming I/O over a plain TCP connection idiomatic. Building with `CGO_ENABLED=0`
produces a single statically linked binary that runs on Alpine with no runtime dependencies.
Go's error-handling model also makes it straightforward to write fail-closed code where every
error path explicitly decides what to do with partial state.

---

## How Does the Program Handle 4 GB Files Not Fitting Into Memory?

The sender reads the source file in 1 MB chunks using `io.ReadFull` into a fixed buffer.
Each chunk is encrypted independently and written to the TCP connection before the next chunk
is read. The receiver allocates a new plaintext slice per chunk via `gcm.Open` and writes it
directly to disk before reading the next frame. At no point is more than one chunk of plaintext
held in memory. Total memory usage is constant regardless of file size.

---

## How Does the Program Implement Resumability?

The sender generates a 16-byte random session ID on the first run and persists it to a JSON
file in the sessions directory. On every reconnect the sender reloads this session ID and
includes it in the RSA-OAEP envelope. The receiver stores a JSON state file keyed by the
session ID hex after each verified chunk, recording how many chunks have been successfully
written to the temp file. On reconnect the receiver reads this state file and sends the
verified chunk count back to the sender as a resume index. The sender then seeks to
`resume_chunk * chunk_size` in the source file and begins encrypting from that offset. The
receiver seeks to the same offset in the temp file and resumes writing there.

---

## How Is Transfer Interference and Resumability Simulated?

`docker compose kill sender` terminates the sender container mid-transfer. The receiver
detects the broken connection via a read error, closes the connection, but retains the `.tmp`
file and `.state` file because the `success` flag was never set to true. `docker compose start
sender` followed by re-running the sender command demonstrates resumption. The receiver logs
`resuming session ... from chunk N of M` where N is greater than zero, proving the transfer
continued from the last checkpoint rather than starting over. This is documented step-by-step
in SMOKE_TEST.md Test 2.

---

## How Does the Program Support the CIAA Framework?

### Confidentiality

Every chunk of the file is encrypted with AES-256-GCM on the sender before it enters the TCP
stream. The AES session key itself is wrapped in an RSA-OAEP envelope encrypted under the
receiver's 4096-bit RSA public key. A passive eavesdropper recording the full TCP stream sees
only ciphertext and an opaque RSA blob. Without the receiver's private key the session key
cannot be recovered and the file contents cannot be read.

### Integrity

AES-256-GCM produces a 16-byte authentication tag for each chunk. Any modification to a chunk
in transit causes `gcm.Open` to return an error before the plaintext reaches disk. After all
chunks are received the receiver re-reads the entire temp file and computes a SHA-256 hash of
the full plaintext, comparing it against the expected hash sent in the encrypted session info
header. A mismatch at either layer causes the receiver to abort and remove the partial file.

### Authenticity

The sender signs `SHA-256(rsa_ciphertext)` with its RSA private key using RSA-PSS. The receiver
verifies this signature against the known sender public key before proceeding with decryption or
accepting any file data. This means only the party holding the sender's private key can
initiate a valid session. The sender wraps the session key under the receiver's known public key
so only the correct receiver can unwrap it. Both directions of identity are verified before
any file data is exchanged.

### Availability

The resumable transfer design directly addresses availability on unstable links. A connection
drop at any point leaves the partial transfer in a recoverable state. The sender retries
connection attempts up to five times using exponential backoff starting at one second and
capped at thirty seconds. The receiver never discards a partially received transfer unless the
AEAD tag or SHA-256 check explicitly fails.

---

## How Are Each of the Threat Models Addressed?

### Passive Eavesdropper Recording the Entire TCP Stream

All file bytes are encrypted with AES-256-GCM before leaving the sender. The AES key is
never transmitted in plaintext. It is wrapped in an RSA-OAEP ciphertext that can only be
unwrapped by the receiver's private key. Recording the full TCP stream yields only ciphertext
that cannot be decrypted without the receiver's private key.

### Active Man-in-the-Middle Modifies Bytes Mid-Flight

Each AES-GCM chunk carries a 16-byte authentication tag computed over the ciphertext. Any
in-flight modification to any bit of any chunk causes `gcm.Open` to return an authentication
error. The receiver immediately logs the failure and closes the connection. The fail-closed
defer removes the partial file so no corrupted data reaches disk. The end-to-end SHA-256 check
at the file level provides a second independent verification layer.

### Attacker Spoofs the Sender or the Receiver

The receiver verifies the RSA-PSS signature over the RSA-OAEP ciphertext as the first
action after reading the session header. An attacker who cannot produce a signature valid under
the sender's public key is rejected before the receiver decrypts any session data or processes
any file chunks. The sender encrypts the session key under the receiver's known public key so
an attacker posing as a receiver cannot unwrap the session key without the matching private key.

### Replay of an Earlier Valid Transfer

Every TCP connection generates a fresh AES-256 session key. A ciphertext stream captured from
one connection fails AEAD verification on any subsequent connection because the receiver uses a
different AES key to attempt decryption. Beyond that the protocol is bidirectional. After
decrypting the session header the receiver sends a resume chunk index to the sender. A recorded
stream cannot complete this exchange so purely passive replay is not possible.

### Connection Drops at 80% Transferred

The receiver persists a state file after each verified chunk and retains the temp file on any
connection error. On reconnect the receiver reads the state file and sends the last verified
chunk count to the sender. The sender resumes from that offset rather than restarting. The
final file only appears on disk after `os.Rename` succeeds on a temp file that has passed both
per-chunk AEAD verification and the end-to-end SHA-256 check.

### Untrusted Intermediary (Broker or Object Store)

Application-layer encryption is the key property here. The file is encrypted on the sender
before it enters the network. A broker or storage tier that receives or proxies the TCP stream
only ever sees AES-256-GCM ciphertext. The broker has no access to the RSA private keys and
therefore no access to the AES session key. Any tampering with the stored or forwarded
ciphertext is detected by the per-chunk AEAD tags on the receiver side.

---

## How Are Each of the Stretch Features Implemented?

### Defense Against Malicious Broker

Because encryption happens at the application layer before the bytes enter the TCP stream a
broker in the data path cannot read the plaintext regardless of how it is compromised. Any
modification to the ciphertext by a broker invalidates the AES-GCM authentication tag for
that chunk and the receiver detects the tampering and aborts.

### Rate-Limited Retry and Backoff

The sender wraps the entire session attempt in a retry loop in `runTransfer`. On any
connection or transfer error the sender waits an increasing delay before the next attempt.
The delay starts at one second, doubles on each failure, and is capped at thirty seconds.
The loop runs for up to five attempts matching the behaviour in Approach A.

### Throughput Measurement

Both the sender and receiver log progress every 100 MB. Each log line includes the completion
percentage, the cumulative bytes transferred in MB, and the throughput in MB per second computed
over the interval since the last log line. A final summary line logs the total MB transferred,
elapsed seconds, and average MB per second for the full session.

### Resumable Transfer Using Signed Chunk Offsets

Each chunk is authenticated with an AES-GCM tag derived from the chunk index acting as an
implicit sequence number. The receiver only advances its state file after verifying the tag,
which means `chunks_verified` in the state file always refers to a contiguous prefix of
authenticated plaintext. On resumption the sender seeks to the byte offset implied by the
verified chunk count and the receiver seeks the temp file write pointer to the same position.

### Forward Secrecy

Each TCP connection generates a fresh AES-256 key via `crypto/rand`. This key is never
reused across connections. A long-term compromise of the RSA private keys after a transfer
completes does not allow decryption of the session ciphertext because the ephemeral AES key
is never persisted anywhere. This is per-connection forward secrecy achieved without an
interactive Diffie-Hellman exchange.

---

## How Are the Core Assessment Requirements Met?

### 2 Programs for Each Approach

`cmd/sender/main.go` and `cmd/receiver/main.go` compile to independent binaries. Each is
built in its own Dockerfile via a multi-stage build.

### Streaming of Data

The sender reads the file in 1 MB chunks via `io.ReadFull` and encrypts and transmits each
chunk before reading the next. The receiver decrypts each incoming frame before reading the
next. Neither program buffers the full file.

### Verifying the Exact File Is Received

The sender pre-computes `SHA-256(plaintext)` of the full source file and includes it in the
encrypted session info header. The receiver re-reads the complete temp file after the final
chunk and computes its own SHA-256. Only if the two digests match does the receiver call
`os.Rename` to produce the final file.

### Authenticating Receiver and Sender

The sender encrypts the session key under the receiver's known RSA public key so the session
key is only recoverable by the correct receiver. The sender signs the RSA ciphertext with its
own RSA private key via RSA-PSS and the receiver verifies this signature before accepting any
data. Both directions of authentication are completed before any file bytes are transferred.

### Required Use of Authenticated Encryption (AEAD)

AES-256-GCM is used for every chunk and for the session info header. There is no use of CBC,
CTR, or any unauthenticated mode. The GCM tag is verified by `gcm.Open` before the plaintext
is written to disk.

### Which Crypto Libraries Are Used

All cryptography comes from the Go standard library. No third-party packages are used.

| Package          | Purpose                                                          |
|------------------|------------------------------------------------------------------|
| `crypto/rsa`     | RSA-OAEP session key encryption and RSA-PSS signature           |
| `crypto/aes`     | AES-256 block cipher initialisation                             |
| `crypto/cipher`  | GCM mode wrapping the AES block cipher for AEAD                 |
| `crypto/sha256`  | Hash function used in OAEP, PSS, and end-to-end file integrity  |
| `crypto/rand`    | Cryptographically secure random bytes for keys, nonces, IDs     |
| `crypto/x509`    | PEM key parsing                                                 |

### Resumable or Fail-Safe Transfers

This approach implements full resumability. The receiver persists a state file after each
verified chunk. On reconnect it offers the sender a non-zero resume offset. If verification
ultimately fails the fail-closed defer removes both the temp file and the state file so no
partial or corrupted data remains on disk.
