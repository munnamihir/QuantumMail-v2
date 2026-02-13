# QuantumMail (MVP demo)

QuantumMail turns sensitive email content into **secure message links**:
- You encrypt locally (in-browser)
- The server stores **ciphertext only**
- Recipients decrypt locally in their browser

This repo includes:
- **Portal** (`/portal`): compose, PQC keygen, decrypt
- **Server** (`/server`): stores encrypted blobs + serves the portal
- **Chrome Extension** (`/extension`): a floating “Encrypt” button for Gmail/Outlook web

> ⚠️ **Demo only**: this code is not audited and should not be used to protect high-value production data yet.

## Crypto modes

- **PQC mode** (recommended for the pitch):
  - ML-KEM-768 (post-quantum KEM) encapsulates an AES-256-GCM key to the recipient’s public key.
  - Recipient uses private seed to decapsulate and decrypt.
- **Passphrase mode**:
  - AES key derived via PBKDF2-SHA256.
  - Good for quick sharing when the recipient doesn’t have keys.

## Quickstart

1) Install deps

```bash
npm install
```

2) Run server + portal

```bash
npm run dev
```

Open:
- Compose: `http://localhost:5173/portal/compose.html`
- Keygen: `http://localhost:5173/portal/keygen.html`

## Chrome extension (MV3)

1) Run the server (`npm run dev`).
2) In Chrome, open `chrome://extensions` → enable **Developer mode**.
3) Click **Load unpacked** → select the `extension/` folder.
4) Open Gmail or Outlook web. You’ll see a floating **QuantumMail** button.

### Permissions note
The extension is scoped to:
- `https://mail.google.com/*`
- `https://outlook.office.com/*`
- `https://outlook.live.com/*`
- and can upload ciphertext to `http://localhost:5173/*` (configurable in the modal).

## Roadmap (what to build next)

- Add **digital signatures** (ML-DSA) to authenticate sender + prevent tampering.
- Add **recipient verification** + key directory (enterprise SSO, SCIM).
- Add **policy controls**: expiry, revoke, DLP, watermarking, audit logs.
- Add **crypto-agility** (algorithm negotiation, rotation).
- Security review + penetration test.

## License

MIT (see `LICENSE`).
