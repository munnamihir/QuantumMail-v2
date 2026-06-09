# QuantumMail v2 🔐

> Organization-based encrypted email for teams that handle sensitive communications.

QuantumMail sits inside Gmail and Outlook as a Chrome extension. You write your email normally, select recipients from your org, hit encrypt — the email body is replaced with a secure QuantumMail link. Recipients click the link, log in with their org credentials, and read the decrypted message. No new email system. No complicated setup. Just encrypted links inside the email clients your team already uses.

![JavaScript](https://img.shields.io/badge/JavaScript-ES2022-yellow?style=flat-square&logo=javascript)
![Node](https://img.shields.io/badge/Node.js-22-green?style=flat-square&logo=node.js)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue?style=flat-square&logo=postgresql)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/status-beta-orange?style=flat-square)

---

## How it works

```
Sender writes email
       ↓
Chrome extension encrypts with AES-256-GCM
Per-recipient keys wrapped with RSA-OAEP
       ↓
Email body replaced with QuantumMail link
       ↓
Recipient clicks link → logs in → extension decrypts
       ↓
Message readable only by org members
```

The server never sees plaintext. Keys are generated and used client-side. Even if the server is compromised, messages stay encrypted.

---

## Features

**For members**
- One-click encryption from Gmail or Outlook
- Secure inbox — read encrypted messages at any time
- Attachment encryption
- Works across devices via device key registration

**For admins**
- Org management dashboard — add, remove, invite members
- Audit trail — every encrypt, decrypt, and login logged
- Security alerts — failed logins, denied decrypts
- Analytics — active seats, key coverage, usage trends
- Policy controls — enforce key rotation, require re-auth for decrypt

**For the platform**
- Multi-org, multi-company architecture
- Super admin console for platform operators
- Quorum recovery — 2-of-3 trusted devices must approve re-access to old messages if a device is lost
- Ed25519 cryptographic signatures for recovery approval
- bcrypt password hashing
- HMAC-SHA256 token signing

---

## Architecture

```
QuantumMail-v2/
├── extension/          Chrome extension (encrypt, decrypt, device vault)
│   ├── content.js      Gmail/Outlook DOM injection
│   ├── popup.js        Extension UI
│   ├── qmVault.js      Recovery vault client
│   └── wrapDek.js      Per-recipient key wrapping
├── outlook-addin/      Outlook Web Add-in (same flow as extension)
├── portal/             Web portal (login, inbox, admin, org management)
│   ├── index.js        Login / signup
│   ├── inbox.js        Encrypted inbox
│   ├── admin.js        Admin dashboard
│   ├── decrypt.js      Message decryption page
│   ├── guard.js        Auth module
│   └── util.js         Web Crypto API helpers
├── server/             Express API (Node.js ES modules)
│   ├── server.js       Main app — all routes, auth, KEK keyring
│   ├── db.js           Neon/PostgreSQL pool
│   ├── orgStore.js     JSONB org store
│   ├── mailer.js       Email via Brevo
│   └── routes/
│       ├── devices.js          Device registration and trust
│       ├── recovery.js         Password reset flow
│       ├── recoveryQuorum.js   Multi-device quorum recovery
│       └── recoveryVault.js    Encrypted key vault
└── scripts/
    └── copy-vendors.js   Copies mlkem.js to extension and portal
```

---

## Security model

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Message encryption | AES-256-GCM | Encrypts message content |
| Key wrapping | RSA-OAEP-SHA256 | Wraps DEK per recipient |
| Server-side envelope | AES-256-GCM + KEK | Protects sealed messages at rest |
| Password hashing | bcrypt (cost 12) | User credentials |
| Token signing | HMAC-SHA256 | Session tokens |
| Recovery approval | Ed25519 signatures | Quorum device verification |
| OTP verification | HMAC-SHA256 | Email-based verification |

See [security.md](./security.md) for full cryptographic documentation.

---

## Quorum recovery

If a user loses their device, they can recover access to old encrypted messages using quorum recovery:

1. User initiates recovery from a new device
2. A second trusted device receives the approval request
3. The second device signs the nonce with its Ed25519 key
4. Server verifies the signature and approves recovery
5. The encrypted vault is returned — valid for 15 minutes
6. User's new device decrypts the vault and re-wraps message keys

No single admin can approve recovery alone. The vault is marked COMPLETED after first fetch — it cannot be replayed.

---

## Getting started

### Prerequisites
- Node.js 22+
- PostgreSQL 15+ (or a [Neon](https://neon.tech) database — free tier works)
- [Brevo](https://brevo.com) account for transactional email (free tier works)

### 1. Clone and install

```bash
git clone https://github.com/munnamihir/QuantumMail-v2
cd QuantumMail-v2
npm install
cd server && npm install
```

### 2. Configure environment

```bash
cp server/.env.example server/.env
```

Edit `server/.env`:

```env
DATABASE_URL=postgresql://...        # Neon or local Postgres
QM_TOKEN_SECRET=<32+ char secret>    # Random string, min 32 chars
QM_PLATFORM_ORG_ID=platform          # Your platform org ID
QM_BOOTSTRAP_SECRET=<32+ char>       # For creating first super admin
QM_ALLOWED_WEB_ORIGINS=https://your-domain.com
PUBLIC_BASE_URL=https://your-domain.com
BREVO_API_KEY=xkeysib-...            # From Brevo dashboard
BREVO_SENDER_EMAIL=noreply@yourdomain.com
BREVO_SENDER_NAME=QuantumMail
```

### 3. Start the server

```bash
cd server
node server.js
```

Server starts on port 10000 by default (configurable via `PORT` env var).

### 4. Bootstrap the platform

Create your first super admin:

```bash
curl -X POST https://your-domain.com/bootstrap/superadmin \
  -H "Content-Type: application/json" \
  -H "X-QM-Bootstrap: your-bootstrap-secret" \
  -d '{"username":"superadmin","password":"your-secure-password"}'
```

### 5. Install the Chrome extension

- Open Chrome → `chrome://extensions`
- Enable Developer Mode
- Click "Load unpacked" → select the `extension/` folder

---

## Deploying to Render

1. Create a new **Web Service** on [render.com](https://render.com)
2. Connect your GitHub repo
3. Set build command: `cd server && npm install`
4. Set start command: `node server/server.js`
5. Add all environment variables from `.env.example`
6. Deploy

Render's free tier spins down after inactivity. Use [UptimeRobot](https://uptimerobot.com) (free) to ping your `/health` endpoint every 5 minutes and keep it warm.

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | ✅ | PostgreSQL connection string |
| `QM_TOKEN_SECRET` | ✅ | HMAC secret for session tokens (min 32 chars) |
| `QM_PLATFORM_ORG_ID` | ✅ | Platform org identifier |
| `QM_BOOTSTRAP_SECRET` | ✅ | Secret for bootstrapping super admin (min 32 chars) |
| `QM_ALLOWED_WEB_ORIGINS` | ✅ prod | Comma-separated allowed CORS origins |
| `PUBLIC_BASE_URL` | ✅ prod | Your public URL (used in email links) |
| `BREVO_API_KEY` | ✅ | Brevo transactional email API key |
| `BREVO_SENDER_EMAIL` | ✅ | Sender email address |
| `BREVO_SENDER_NAME` | ✅ | Sender display name |
| `QM_EXTENSION_ID` | recommended | Chrome extension ID for CORS |
| `PORT` | optional | Server port (default 10000) |
| `NODE_ENV` | optional | `production` or `development` |

---

## API reference

```
POST /auth/login                          Login
GET  /auth/me                             Current user
POST /auth/signup                         Signup via invite
POST /auth/forgot-password                Password reset
POST /auth/reset/send-code                OTP for reset
POST /auth/reset/confirm                  Confirm reset

GET  /org/check                           Check org exists
GET  /org/users                           List org members
POST /org/register-key                    Register device public key

POST /api/messages                        Store encrypted message
GET  /api/inbox                           List messages
GET  /api/messages/:id                    Fetch + decrypt message

POST /api/devices/register                Register device
POST /api/devices/trust                   Activate device
POST /api/devices/revoke                  Revoke device
GET  /api/devices/list                    List devices

POST /api/recovery/init                   Init vault token
PUT  /api/recovery/vault                  Store encrypted vault
GET  /api/recovery/vault                  Read vault
POST /api/recovery/quorum/start           Start quorum recovery
POST /api/recovery/quorum/approve         Approve with Ed25519 signature
POST /api/recovery/quorum/fetch           Fetch vault after approval

GET  /admin/users                         List members (admin)
POST /admin/invites/generate              Generate invite code
GET  /admin/audit                         Audit log
GET  /admin/alerts                        Security alerts
GET  /admin/analytics                     Usage analytics
GET  /admin/policies                      Org policies

GET  /super/org-requests                  Pending org requests
POST /super/org-requests/:id/approve      Approve org
POST /super/org-requests/:id/reject       Reject org
```

---

## Roadmap

- [ ] Firefox extension
- [ ] Mobile app (React Native)
- [ ] Slack and email alert delivery
- [ ] SCIM provisioning for enterprise SSO
- [ ] SOC 2 audit preparation
- [ ] Self-hosted Docker deployment
- [ ] Configurable quorum threshold (2-of-N)
- [ ] Message expiry / burn-after-reading

---

## Contributing

Issues and PRs welcome. High-value areas:

- Additional email client support (Thunderbird, Apple Mail)
- Self-hosted deployment guide
- Security review and penetration testing
- UI improvements in the portal

Please open an issue before starting large changes.

---

## License

MIT — see [LICENSE](./LICENSE)

---

Built by [@munnamihir](https://github.com/munnamihir) · [quantummail-v2.onrender.com](https://quantummail-v2.onrender.com)
