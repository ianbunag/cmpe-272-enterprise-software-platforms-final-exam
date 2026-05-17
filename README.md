# Secure File Transfer

Two distinct implementations for securely transferring a 4 GB file over an untrusted
network, satisfying Confidentiality, Integrity, Authenticity, and Availability.

## Demo video
https://youtu.be/E7eTa5m6DVw

## AI Usage

| Document | Description |
|---|---|
| [AI_NOTES.md](AI_NOTES.md) | How Claude and other AI tools were directed across both approaches — prompting strategy, review process, and each tool's role. |
| [AI_USAGE_WRITEUP.md](AI_USAGE_WRITEUP.md) | Evaluation of Claude's performance — what it wrote end-to-end, a concrete example of catching a mistake, and one thing it did better and worse than expected. |

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

---

## Approach B — Hybrid RSA-AES Envelope

The sender generates a fresh AES-256 session key per connection, wraps it in an RSA-OAEP
envelope encrypted under the receiver's 4096-bit public key, and signs the envelope with its
own RSA private key for mutual authentication. File data is streamed in 1 MB chunks over a
plain TCP connection, each chunk independently encrypted with AES-256-GCM using a nonce
derived from the chunk index. The receiver persists a state file after each verified chunk so
a killed transfer can resume from the last checkpoint rather than restarting from zero.

| Document | Description |
|---|---|
| [QUICKSTART.md](approach-b-hybrid-aes/QUICKSTART.md) | Get Approach B running end-to-end in under 5 minutes. Start here. |
| [SMOKE_TEST.md](approach-b-hybrid-aes/SMOKE_TEST.md) | Three test cases covering successful transfer, mid-transfer resumption, and attacker rejection. Run these to verify correctness. |
| [DESIGN.md](approach-b-hybrid-aes/DESIGN.md) | Architecture diagram, wire protocol, key management, chunking and nonce derivation, exact algorithms and parameters, and the full threat model table. |
| [CHECKLIST.md](approach-b-hybrid-aes/CHECKLIST.md) | Answers every design question from the assessment checklist — language choice, memory handling, resumability, CIAA coverage, threat model responses, stretch features, and crypto library decisions. |

## Prompting approach
<img width="863" height="566" alt="Screenshot 2026-05-17 at 11 53 15" src="https://github.com/user-attachments/assets/8e3070bc-356d-4414-bdc3-095902d19108" />

