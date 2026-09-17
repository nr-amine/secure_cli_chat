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

### How the Encryption Works
1. **RSA Key Pair:** When a client starts, it generates a 2048-bit RSA key pair and registers its public key with the server directory.
2. **AES-GCM for Messages:** When sending a direct message (`/msg`), the client creates a fresh random 128-bit AES key and a 12-byte random nonce. The message is encrypted using AES-GCM (so the recipient can verify it wasn't tampered with).
3. **Sending the Key:** The AES key itself is encrypted with the recipient's RSA public key (using OAEP padding). Both the encrypted key, the nonce, and the ciphertext are bundled together and sent over the socket.

### Socket Message Framing (`protocol.py`)
Instead of using fragile string delimiters (like splitting on `//`), every message is sent with a 4-byte prefix indicating its length. This ensures the receiver reads the exact message size without cutting off packets or mixing up binary data.

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
Listens on `127.0.0.1:1234` with thread-safe client routing (`threading.Lock`).

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

## Known Limitations

* **Central directory trust:** The server stores and gives out public keys, but there are no certificates or key fingerprint checks. A rogue server could theoretically swap someone's public key (man-in-the-middle).
* **No forward secrecy:** Because messages are encrypted with the recipient's main RSA key, if that private key is ever exposed, past recorded messages could be decrypted. Adding Diffie-Hellman key exchange would fix this.
* **Public channel is cleartext:** Normal messages without `/msg` are intentionally broadcast unencrypted like an open chat room.

