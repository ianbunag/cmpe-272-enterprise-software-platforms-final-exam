# Secure File Transfer

Two distinct implementations for securely transferring a 4 GB file over an untrusted
network, satisfying Confidentiality, Integrity, Authenticity, and Availability.

---

## Approach A — mTLS Streaming

Sender and receiver authenticate each other with mutual TLS 1.3. The file is streamed
in 32 KB chunks directly over the encrypted channel. A SHA-256 hash computed on both
ends confirms the file arrived intact.

| Document | Description |
|---|---|
| [QUICKSTART.md](approach-a-mtls/QUICKSTART.md) | Get Approach A running end-to-end in under 5 minutes. Start here. |
| [SMOKE_TEST.md](approach-a-mtls/SMOKE_TEST.md) | Three test cases covering retry backoff, mid-transfer failure cleanup, and attacker rejection. Run these to verify correctness. |
| [DESIGN.md](approach-a-mtls/DESIGN.md) | Architecture diagram, key exchange, chunking and framing, exact algorithms and parameters, and the full threat model table. |
| [CHECKLIST.md](approach-a-mtls/CHECKLIST.md) | Answers every design question from the assessment checklist — language choice, memory handling, CIAA coverage, threat model responses, and crypto library decisions. |
