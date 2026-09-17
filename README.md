# Secure CLI Chat

A terminal-based end-to-end encrypted messaging application built in Python. Combines a multithreaded TCP server directory with hybrid cryptography (RSA-2048 OAEP and AES-128-GCM) to protect direct peer-to-peer communications.

---

## Architecture & Cryptography

```
                    ┌─────────────────────────┐
                    │   Directory Server      │
                    │   (Public Key Registry) │
                    └───────┬─────────┬───────┘
          Length-Prefixed   │         │  Length-Prefixed
          TCP Frame         │         │  TCP Frame
                            ▼         ▼
                 ┌──────────────┐   ┌──────────────┐
                 │ Client Alice │   │  Client Bob  │
                 └──────────────┘   └──────────────┘
                        │                  ▲
                        └─ Encrypted DM ───┘
                           (via Relay)
```

### Hybrid Cryptosystem
1. **Asymmetric Key Exchange:** Each client generates an ephemeral 2048-bit RSA key pair on startup (`e = 65537`). The public key is serialized to PEM format and registered with the server directory.
2. **Symmetric Payload Encryption (AEAD):** Direct messages (`/msg`) generate an ephemeral 128-bit AES key and a 96-bit cryptographically secure random nonce (`os.urandom(12)`). Payloads are encrypted using **AES-GCM**, providing authenticated encryption with integrity guarantees.
3. **Key Encapsulation:** The AES session key is wrapped using **RSA-OAEP** with SHA-256 and MGF1, then bundled with the nonce and ciphertext into a Base64 payload.

### Length-Prefixed Protocol Framing (`protocol.py`)
Rather than fragile string delimiters, all messages are framed over the wire using a 4-byte big-endian length prefix:
```
[ 4-byte Big-Endian Length (N) ] [ N bytes of UTF-8 JSON Payload ]
```
This guarantees strict TCP stream framing and eliminates packet fragmentation or truncation bugs across varying payload sizes.

---

## Usage

### Dependencies
```bash
pip install cryptography
```

### 1. Start the Server
```bash
python server.py
```
Listens on `127.0.0.1:1234` with synchronized thread-safe client routing (`threading.Lock`).

### 2. Launch Clients
In separate terminals:
```bash
python client.py
```

### Client Commands
* `/users` — Lists all connected users.
* `/getkey <username>` — Fetches and caches the recipient's RSA public key from the directory.
* `/msg <username> <message>` — Encrypts and transmits an end-to-end encrypted message.
* `<message>` — Broadcasts a cleartext message to all connected clients.
* `exit` — Disconnects and exits.

---

## Running Automated Tests

An automated end-to-end integration test verifying registration, public key caching, hybrid encryption/decryption, and broadcast relay:

```bash
python -m unittest test_chat.py
```

---

## Known Security Limitations & Design Trade-offs

* **Untrusted Directory & Lack of PKI:** The central server acts as an unauthenticated key directory. A compromised or malicious server could substitute public keys (Man-In-The-Middle). Production deployment requires public key fingerprint verification (TOFU) or digital signatures.
* **No Perfect Forward Secrecy (PFS):** Session keys are encrypted under the recipient's static session RSA key. Compromise of the private key would expose previously recorded messages. Implementing Ephemeral Diffie-Hellman (X25519) would provide forward secrecy.
* **Cleartext Broadcast Channel:** Unprefixed messages are intentionally broadcast in cleartext across the network for public chat room functionality; only direct `/msg` communications are encrypted.

