# Architecture (MVP)

## Components

- **Portal (browser)**
  - `/portal/compose.html` — encrypts plaintext, uploads ciphertext
  - `/portal/keygen.html` — generates ML-KEM keys (public + private seed)
  - `/m/<id>` — decrypts locally using passphrase or ML-KEM private seed

- **Server** (`/server/index.js`)
  - Stores encrypted payloads in `server/data/messages.json`
  - Serves portal static assets

- **Extension** (`/extension`)
  - Content script injects a lightweight modal UI on Gmail/Outlook web
  - Background service worker performs crypto and uploads ciphertext

## PQC flow (ML-KEM-768 + AES-256-GCM)

1. Recipient generates keypair; shares **public key** out of band.
2. Sender imports recipient public key.
3. Sender uses ML-KEM **encapsulateKey** to derive an AES key + KEM ciphertext.
4. Sender encrypts message with **AES-GCM** and uploads ciphertext + IV + KEM ciphertext.
5. Recipient uses private seed to import key and **decapsulateKey** to recover AES key, then decrypts.

## Passphrase flow (PBKDF2 + AES-256-GCM)

1. Sender derives AES key from passphrase using PBKDF2-SHA256 + random salt.
2. Sender encrypts with AES-GCM and uploads ciphertext + IV + salt.
3. Recipient enters passphrase; derives key and decrypts.

## Notes

- This MVP does not yet authenticate the sender. Add **ML-DSA** signatures for authenticity & anti-tamper.
- Add link expiry/revocation + access controls for enterprise use.
