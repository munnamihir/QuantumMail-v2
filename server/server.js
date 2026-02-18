import express from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { nanoid } from "nanoid";
import cors from "cors";


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// ---- CORS (Chrome extension + portal) ----
// Put your extension ID here:
const EXTENSION_ID = process.env.QM_EXTENSION_ID || "cfofgajelokgkofefofgpllaockghgjg";

// Optional: add any web origins you use (portal, codespaces, etc.)
const ALLOWED_WEB_ORIGINS = [
  "https://quantummail-v2.onrender.com",
  "http://localhost:5173"
];

function isAllowedOrigin(origin) {
  if (!origin) return true; // allow server-to-server, curl, etc.

  // Allow the Chrome extension origin:
  if (origin === `chrome-extension://${EXTENSION_ID}`) return true;

  // Allow your portal / dev origins:
  if (ALLOWED_WEB_ORIGINS.includes(origin)) return true;


  return false;
}

app.use(cors({
  origin: (origin, cb) => {
    if (isAllowedOrigin(origin)) return cb(null, true);
    return cb(new Error(`CORS blocked origin: ${origin}`));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: false
}));

// IMPORTANT: handle preflight requests
app.options("*", cors());


app.use(express.json({ limit: "25mb" }));

// ----------------------------
// Paths
// ----------------------------
const portalDir = path.join(__dirname, "..", "portal");
const dataPath = path.join(__dirname, "data.json");

// ----------------------------
// Persistence (data.json)
// ----------------------------
function loadData() {
  try {
    if (!fs.existsSync(dataPath)) return { orgs: {} };
    return JSON.parse(fs.readFileSync(dataPath, "utf8"));
  } catch {
    return { orgs: {} };
  }
}
function saveData() {
  fs.writeFileSync(dataPath, JSON.stringify(DB, null, 2), "utf8");
}

const DB = loadData();
if (!DB.orgs) DB.orgs = {};

// ----------------------------
// Helpers
// ----------------------------
function nowIso() { return new Date().toISOString(); }

function sha256(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function timingSafeEq(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function b64urlEncode(bufOrStr) {
  const buf = Buffer.isBuffer(bufOrStr) ? bufOrStr : Buffer.from(String(bufOrStr), "utf8");
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64urlDecodeToString(s) {
  const str = String(s || "");
  const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + pad;
  return Buffer.from(b64, "base64").toString("utf8");
}
function bytesToB64(buf) { return Buffer.from(buf).toString("base64"); }
function b64ToBytes(b64) { return Buffer.from(String(b64 || ""), "base64"); }

// ----------------------------
// Minimal JWT-like token (HMAC-SHA256)
// ----------------------------
const TOKEN_SECRET = process.env.QM_TOKEN_SECRET || "dev_secret_change_me";

function signToken(payload) {
  const header = { alg: "HS256", typ: "JWT" };
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", TOKEN_SECRET).update(`${h}.${p}`).digest();
  const s = b64urlEncode(sig);
  return `${h}.${p}.${s}`;
}

function verifyToken(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;

  const sig = crypto.createHmac("sha256", TOKEN_SECRET).update(`${h}.${p}`).digest();
  const expected = b64urlEncode(sig);
  if (!timingSafeEq(expected, s)) return null;

  const payload = JSON.parse(b64urlDecodeToString(p));
  if (payload.exp && Date.now() > payload.exp * 1000) return null;
  return payload;
}

// ----------------------------
// Public base URL helper
// ----------------------------
function getPublicBase(req) {
  const proto = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
}

// ----------------------------
// Org + policies + alerts
// ----------------------------
function defaultPolicies() {
  return {
    forceAttachmentEncryption: false,
    disablePassphraseMode: false,        // flag for future (your decrypt still uses login anyway)
    enforceKeyRotationDays: 0,           // 0 = off
    requireReauthForDecrypt: true        // you already do login+decrypt; keep true
  };
}

function getOrg(orgId) {
  const oid = String(orgId || "").trim();
  if (!oid) return null;

  if (!DB.orgs[oid]) {
    DB.orgs[oid] = {
      users: [],
      audit: [],
      messages: {},
      keyring: null,
      policies: defaultPolicies()
    };
  }

  const org = DB.orgs[oid];
  if (!org.users) org.users = [];
  if (!org.audit) org.audit = [];
  if (!org.messages) org.messages = {};
  if (!org.policies) org.policies = defaultPolicies();

  ensureKeyring(org);
  saveData();
  return org;
}

// ----------------------------
// Audit log
// ----------------------------
function audit(req, orgId, userId, action, details = {}) {
  const org = getOrg(orgId);
  if (!org) return;

  const entry = {
    id: nanoid(10),
    at: nowIso(),
    orgId,
    userId: userId || null,
    action,
    ip: req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "",
    ua: req.headers["user-agent"] || "",
    ...details
  };

  org.audit.unshift(entry);
  if (org.audit.length > 2000) org.audit.length = 2000;
  saveData();
}

// ----------------------------
// KEK keyring (server-side at-rest encryption)
// ----------------------------
function randomKey32() { return crypto.randomBytes(32); }

function sealWithKek(kekBytes, obj) {
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from("quantummail:kek:v1", "utf8");

  const cipher = crypto.createCipheriv("aes-256-gcm", kekBytes, iv);
  cipher.setAAD(aad);

  const pt = Buffer.from(JSON.stringify(obj), "utf8");
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();

  return { ivB64: bytesToB64(iv), ctB64: bytesToB64(ct), tagB64: bytesToB64(tag) };
}

function openWithKek(kekBytes, sealed) {
  const iv = b64ToBytes(sealed.ivB64);
  const ct = b64ToBytes(sealed.ctB64);
  const tag = b64ToBytes(sealed.tagB64);
  const aad = Buffer.from("quantummail:kek:v1", "utf8");

  const decipher = crypto.createDecipheriv("aes-256-gcm", kekBytes, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);

  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return JSON.parse(pt.toString("utf8"));
}

function ensureKeyring(org) {
  if (!org.keyring) {
    const kek = randomKey32();
    org.keyring = {
      active: "1",
      keys: {
        "1": {
          version: "1",
          status: "active",
          createdAt: nowIso(),
          activatedAt: nowIso(),
          retiredAt: null,
          kekB64: bytesToB64(kek)
        }
      }
    };
    saveData();
  }
}

function getActiveKek(org) {
  ensureKeyring(org);
  const v = String(org.keyring.active);
  const k = org.keyring.keys[v];
  return { version: v, kekBytes: b64ToBytes(k.kekB64), meta: k };
}

function getKekByVersion(org, version) {
  ensureKeyring(org);
  const v = String(version);
  const k = org.keyring.keys[v];
  if (!k) return null;
  return { version: v, kekBytes: b64ToBytes(k.kekB64), meta: k };
}

// ----------------------------
// Auth middleware
// ----------------------------
function requireAuth(req, res, next) {
  const auth = String(req.headers.authorization || "");
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: "Missing Bearer token" });

  const payload = verifyToken(m[1]);
  if (!payload) return res.status(401).json({ error: "Invalid/expired token" });

  const org = getOrg(payload.orgId);
  if (!org) return res.status(401).json({ error: "Unknown org" });

  const user = org.users.find((u) => u.userId === payload.userId);
  if (!user) return res.status(401).json({ error: "Unknown user" });

  if (String(user.status || "Active").toLowerCase() === "disabled") {
    return res.status(403).json({ error: "User disabled" });
  }

  req.qm = { tokenPayload: payload, org, user };
  next();
}

function requireAdmin(req, res, next) {
  if (!req.qm?.user) return res.status(401).json({ error: "Unauthorized" });
  if (req.qm.user.role !== "Admin") return res.status(403).json({ error: "Admin only" });
  next();
}

// ----------------------------
// No-cache for portal + /m
// ----------------------------
app.use((req, res, next) => {
  if (req.path.startsWith("/portal") || req.path.startsWith("/m/")) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("Surrogate-Control", "no-store");
  }
  next();
});

// ----------------------------
// DEV: create admin with custom creds
// POST /dev/seed-admin { orgId, username, password }
// ----------------------------
app.post("/dev/seed-admin", (req, res) => {
  const orgId = String(req.body?.orgId || "").trim();
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");

  if (!orgId || !username || !password) {
    return res.status(400).json({ error: "orgId, username, password required" });
  }

  const org = getOrg(orgId);

  const exists = org.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
  if (exists) return res.status(409).json({ error: "Username already exists" });

  const newAdmin = {
    userId: nanoid(10),
    username,
    passwordHash: sha256(password),
    role: "Admin",
    status: "Active",
    publicKeySpkiB64: null,
    publicKeyRegisteredAt: null,
    createdAt: nowIso(),
    lastLoginAt: null
  };

  org.users.push(newAdmin);
  audit(req, orgId, newAdmin.userId, "create_admin", { username });
  saveData();

  res.json({ ok: true, orgId, userId: newAdmin.userId, username });
});

// ----------------------------
// AUTH: login
// ----------------------------
app.post("/auth/login", (req, res) => {
  const orgId = String(req.body?.orgId || "").trim();
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");

  if (!orgId) return res.status(400).json({ error: "Invalid orgId" });

  const org = getOrg(orgId);
  if (!org) return res.status(400).json({ error: "Invalid orgId" });

  const user = org.users.find((u) => u.username.toLowerCase() === username.toLowerCase());

  // audit failures too (risk alerts)
  if (!user) {
    audit(req, orgId, null, "login_failed", { username, reason: "unknown_user" });
    return res.status(401).json({ error: "Invalid creds" });
  }

  const ph = sha256(password);
  if (!timingSafeEq(ph, user.passwordHash)) {
    audit(req, orgId, user.userId, "login_failed", { username: user.username, reason: "bad_password" });
    return res.status(401).json({ error: "Invalid creds" });
  }

  user.lastLoginAt = nowIso();

  const payload = {
    userId: user.userId,
    orgId,
    role: user.role,
    username: user.username,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60
  };

// ----------------------------
// AUTH: change my password (self-service)
// ----------------------------
app.post("/auth/change-password", requireAuth, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { user } = req.qm;

  const currentPassword = String(req.body?.currentPassword || "");
  const newPassword = String(req.body?.newPassword || "");

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: "currentPassword and newPassword required" });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: "New password must be at least 8 characters" });
  }

  // Verify current password
  const curHash = sha256(currentPassword);
  if (!timingSafeEq(curHash, user.passwordHash)) {
    audit(req, orgId, user.userId, "change_password_failed", { reason: "bad_current_password" });
    return res.status(401).json({ error: "Current password is incorrect" });
  }

  // Prevent same password reuse (optional but nice)
  const nextHash = sha256(newPassword);
  if (timingSafeEq(nextHash, user.passwordHash)) {
    return res.status(400).json({ error: "New password must be different" });
  }

  user.passwordHash = nextHash;
  audit(req, orgId, user.userId, "change_password", { username: user.username, role: user.role });
  saveData();

  res.json({ ok: true });
});

  
  const token = signToken(payload);
  audit(req, orgId, user.userId, "login", { username: user.username, role: user.role });
  saveData();

  res.json({
    token,
    user: {
      userId: user.userId,
      orgId,
      username: user.username,
      role: user.role,
      status: user.status || "Active",
      hasPublicKey: !!user.publicKeySpkiB64,
      lastLoginAt: user.lastLoginAt,
      publicKeyRegisteredAt: user.publicKeyRegisteredAt
    }
  });
});

// ----------------------------
// ORG: register public key
// ----------------------------
app.post("/org/register-key", requireAuth, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { user } = req.qm;

  const publicKeySpkiB64 = String(req.body?.publicKeySpkiB64 || "").trim();
  if (!publicKeySpkiB64) return res.status(400).json({ error: "publicKeySpkiB64 required" });

  user.publicKeySpkiB64 = publicKeySpkiB64;
  user.publicKeyRegisteredAt = nowIso();

  audit(req, orgId, user.userId, "pubkey_register", { username: user.username });
  saveData();

  res.json({ ok: true });
});

// Back-compat alias
app.post("/pubkey_register", requireAuth, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { user } = req.qm;

  const publicKeySpkiB64 = String(req.body?.publicKeySpkiB64 || "").trim();
  if (!publicKeySpkiB64) return res.status(400).json({ error: "publicKeySpkiB64 required" });

  user.publicKeySpkiB64 = publicKeySpkiB64;
  user.publicKeyRegisteredAt = nowIso();

  audit(req, orgId, user.userId, "pubkey_register", { username: user.username });
  saveData();

  res.json({ ok: true });
});

// ORG: list users (extension uses this for wrapping keys)
app.get("/org/users", requireAuth, (req, res) => {
  const { org } = req.qm;
  res.json({
    users: org.users.map((u) => ({
      userId: u.userId,
      username: u.username,
      role: u.role,
      status: u.status || "Active",
      publicKeySpkiB64: u.publicKeySpkiB64 || null,
      hasPublicKey: !!u.publicKeySpkiB64
    }))
  });
});

// ----------------------------
// ADMIN: users
// ----------------------------
app.get("/admin/users", requireAuth, requireAdmin, (req, res) => {
  const { org } = req.qm;
  res.json({
    users: org.users.map((u) => ({
      userId: u.userId,
      username: u.username,
      role: u.role,
      status: u.status || "Active",
      hasPublicKey: !!u.publicKeySpkiB64,
      lastLoginAt: u.lastLoginAt || null,
      publicKeyRegisteredAt: u.publicKeyRegisteredAt || null
    }))
  });
});

app.post("/admin/users", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user: admin } = req.qm;

  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  const role = String(req.body?.role || "Member").trim() || "Member";

  if (!username || !password) return res.status(400).json({ error: "username/password required" });

  const exists = org.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
  if (exists) return res.status(409).json({ error: "Username already exists" });

  const newUser = {
    userId: nanoid(10),
    username,
    passwordHash: sha256(password),
    role: role === "Admin" ? "Admin" : "Member",
    status: "Active",
    publicKeySpkiB64: null,
    publicKeyRegisteredAt: null,
    createdAt: nowIso(),
    lastLoginAt: null
  };

  org.users.push(newUser);
  audit(req, orgId, admin.userId, "create_user", {
    createdUserId: newUser.userId,
    username: newUser.username,
    role: newUser.role
  });
  saveData();

  res.json({ ok: true, userId: newUser.userId });
});

// delete user
app.delete("/admin/users/:userId", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user: admin } = req.qm;

  const targetId = String(req.params.userId || "").trim();
  if (!targetId) return res.status(400).json({ error: "userId required" });

  if (targetId === admin.userId) {
    return res.status(400).json({ error: "You cannot delete your own admin account." });
  }

  const idx = org.users.findIndex((u) => u.userId === targetId);
  if (idx < 0) return res.status(404).json({ error: "User not found" });

  // remove wrapped keys for that user from stored messages (cleanup)
  for (const mid of Object.keys(org.messages || {})) {
    try {
      const rec = org.messages[mid];
      const kv = String(rec.kekVersion || org.keyring.active);
      const kk = getKekByVersion(org, kv);
      if (!kk) continue;

      const msg = openWithKek(kk.kekBytes, rec.sealed);
      if (msg?.wrappedKeys && msg.wrappedKeys[targetId]) {
        delete msg.wrappedKeys[targetId];
        rec.sealed = sealWithKek(kk.kekBytes, msg);
      }
    } catch { /* ignore */ }
  }

  const removed = org.users.splice(idx, 1)[0];
  audit(req, orgId, admin.userId, "delete_user", { deletedUserId: targetId, username: removed.username });
  saveData();

  res.json({ ok: true, deletedUserId: targetId });
});

// clear key
app.post("/admin/users/:userId/clear-key", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user: admin } = req.qm;

  const targetId = String(req.params.userId || "").trim();
  if (!targetId) return res.status(400).json({ error: "userId required" });

  const u = org.users.find((x) => x.userId === targetId);
  if (!u) return res.status(404).json({ error: "User not found" });

  u.publicKeySpkiB64 = null;
  u.publicKeyRegisteredAt = null;

  audit(req, orgId, admin.userId, "clear_user_pubkey", { targetUserId: targetId, username: u.username });
  saveData();

  res.json({ ok: true });
});

// ----------------------------
// ADMIN: audit
// ----------------------------
app.get("/admin/audit", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const limit = Math.min(parseInt(req.query.limit || "200", 10) || 200, 2000);
  const items = req.qm.org.audit.slice(0, limit);
  res.json({ orgId, items });
});

// ----------------------------
// ADMIN: policies
// ----------------------------
app.get("/admin/policies", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  res.json({ orgId, policies: req.qm.org.policies || defaultPolicies() });
});

app.post("/admin/policies", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user: admin } = req.qm;

  const p = req.body || {};
  const cur = org.policies || defaultPolicies();

  org.policies = {
    forceAttachmentEncryption: !!p.forceAttachmentEncryption,
    disablePassphraseMode: !!p.disablePassphraseMode,
    enforceKeyRotationDays: Math.max(0, parseInt(p.enforceKeyRotationDays || cur.enforceKeyRotationDays || 0, 10) || 0),
    requireReauthForDecrypt: !!p.requireReauthForDecrypt
  };

  audit(req, orgId, admin.userId, "policy_update", { policies: org.policies });
  saveData();

  res.json({ ok: true, policies: org.policies });
});

// ----------------------------
// ADMIN: analytics
// ----------------------------
function withinDays(iso, days) {
  if (!iso) return false;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return false;
  const since = Date.now() - days * 24 * 60 * 60 * 1000;
  return t >= since;
}

app.get("/admin/analytics", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const days = Math.min(Math.max(parseInt(req.query.days || "30", 10) || 30, 1), 365);
  const items = req.qm.org.audit.filter(a => withinDays(a.at, days));

  const countByAction = {};
  const userActivity = {}; // userId -> score + per-action
  const attachmentBytesPerDay = {}; // YYYY-MM-DD -> bytes

  for (const a of items) {
    countByAction[a.action] = (countByAction[a.action] || 0) + 1;

    if (a.userId) {
      if (!userActivity[a.userId]) userActivity[a.userId] = { userId: a.userId, decrypts: 0, encrypts: 0, denied: 0, logins: 0, username: a.username || "" };
      if (a.action === "decrypt_payload") userActivity[a.userId].decrypts++;
      if (a.action === "encrypt_store") userActivity[a.userId].encrypts++;
      if (a.action === "decrypt_denied") userActivity[a.userId].denied++;
      if (a.action === "login") userActivity[a.userId].logins++;
    }

    if (a.action === "encrypt_store" && a.attachmentsTotalBytes) {
      const day = String(a.at).slice(0, 10);
      attachmentBytesPerDay[day] = (attachmentBytesPerDay[day] || 0) + Number(a.attachmentsTotalBytes || 0);
    }
  }

  const topUsers = Object.values(userActivity)
    .sort((x, y) => (y.decrypts + y.encrypts) - (x.decrypts + x.encrypts))
    .slice(0, 10);

  // timeseries last N days
  const series = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 24 * 60 * 60 * 1000);
    const day = d.toISOString().slice(0, 10);
    series.push({
      day,
      attachmentBytes: attachmentBytesPerDay[day] || 0
    });
  }

  res.json({
    orgId,
    days,
    counts: {
      encryptedMessages: countByAction["encrypt_store"] || 0,
      decrypts: countByAction["decrypt_payload"] || 0,
      deniedDecrypts: countByAction["decrypt_denied"] || 0,
      failedLogins: countByAction["login_failed"] || 0
    },
    topUsers,
    attachmentSeries: series
  });
});

// ----------------------------
// ADMIN: alerts (risk)
// ----------------------------
app.get("/admin/alerts", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const minutes = Math.min(Math.max(parseInt(req.query.minutes || "60", 10) || 60, 5), 1440);
  const since = Date.now() - minutes * 60 * 1000;

  const recent = req.qm.org.audit.filter(a => {
    const t = Date.parse(a.at);
    return !Number.isNaN(t) && t >= since;
  });

  const denied = recent.filter(a => a.action === "decrypt_denied").length;
  const failedLogins = recent.filter(a => a.action === "login_failed").length;

  const alerts = [];
  if (denied >= 10) alerts.push({ severity: "high", code: "DENIED_DECRYPT_SPIKE", message: `High denied decrypts: ${denied} in last ${minutes} min` });
  else if (denied >= 5) alerts.push({ severity: "medium", code: "DENIED_DECRYPT", message: `Denied decrypts: ${denied} in last ${minutes} min` });

  if (failedLogins >= 10) alerts.push({ severity: "high", code: "LOGIN_FAIL_SPIKE", message: `High failed logins: ${failedLogins} in last ${minutes} min` });
  else if (failedLogins >= 5) alerts.push({ severity: "medium", code: "LOGIN_FAIL", message: `Failed logins: ${failedLogins} in last ${minutes} min` });

  res.json({ orgId, minutes, alerts, summary: { denied, failedLogins } });
});

// ----------------------------
// ADMIN: keyring rotate/retire
// ----------------------------
app.get("/admin/keys", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const org = req.qm.org;

  ensureKeyring(org);

  const keys = Object.values(org.keyring.keys)
    .map((k) => ({
      version: k.version,
      status: k.status,
      createdAt: k.createdAt,
      activatedAt: k.activatedAt,
      retiredAt: k.retiredAt
    }))
    .sort((a, b) => Number(a.version) - Number(b.version));

  res.json({ orgId, active: org.keyring.active, keys });
});

app.post("/admin/keys/rotate", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const org = req.qm.org;
  const adminId = req.qm.user.userId;

  ensureKeyring(org);

  const versions = Object.keys(org.keyring.keys)
    .map((v) => Number(v))
    .filter((n) => !Number.isNaN(n));

  const next = String((Math.max(...versions, 0) + 1) || 1);

  const curV = String(org.keyring.active);
  if (org.keyring.keys[curV]) {
    org.keyring.keys[curV].status = "retired";
    org.keyring.keys[curV].retiredAt = nowIso();
  }

  const kek = randomKey32();
  org.keyring.keys[next] = {
    version: next,
    status: "active",
    createdAt: nowIso(),
    activatedAt: nowIso(),
    retiredAt: null,
    kekB64: bytesToB64(kek)
  };
  org.keyring.active = next;

  audit(req, orgId, adminId, "kek_rotate", { active: next, previous: curV });
  saveData();

  res.json({ ok: true, active: next, previous: curV });
});

// ----------------------------
// MESSAGES: create + fetch (at-rest sealed with KEK)
// ----------------------------
app.post("/api/messages", requireAuth, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user } = req.qm;

  const payload = req.body || {};
  if (!payload.iv || !payload.ciphertext || !payload.wrappedKeys) {
    return res.status(400).json({ error: "Invalid payload (iv, ciphertext, wrappedKeys required)" });
  }

  // enforce attachment policy
  const pol = org.policies || defaultPolicies();
  if (pol.forceAttachmentEncryption) {
    // if attachments provided, validate shape
    if (payload.attachments != null && !Array.isArray(payload.attachments)) {
      return res.status(400).json({ error: "attachments must be an array" });
    }
    const arr = Array.isArray(payload.attachments) ? payload.attachments : [];
    for (const a of arr) {
      if (!a || !a.iv || !a.ciphertext) {
        return res.status(400).json({ error: "attachments must include iv + ciphertext for each file" });
      }
    }
  }

  const id = nanoid(10);
  const createdAt = nowIso();

  const { version, kekBytes, meta } = getActiveKek(org);

  // policy: key rotation reminder (alert via audit)
  const rotateDays = Number(pol.enforceKeyRotationDays || 0);
  if (rotateDays > 0) {
    const activated = Date.parse(meta?.activatedAt || meta?.createdAt || "");
    if (!Number.isNaN(activated)) {
      const ageDays = Math.floor((Date.now() - activated) / (24 * 60 * 60 * 1000));
      if (ageDays >= rotateDays) {
        audit(req, orgId, user.userId, "risk_key_rotation_due", { ageDays, rotateDays, activeKeyVersion: version });
      }
    }
  }

  const attachmentsArr = Array.isArray(payload.attachments) ? payload.attachments : [];
  const attachmentsTotalBytes = attachmentsArr.reduce((sum, a) => sum + Number(a?.size || 0), 0);

  const sealed = sealWithKek(kekBytes, {
    iv: payload.iv,
    ciphertext: payload.ciphertext,
    aad: payload.aad || "gmail",
    wrappedKeys: payload.wrappedKeys,
    attachments: attachmentsArr
  });

  //org.messages[id] = { createdAt, kekVersion: version, sealed };
  org.messages[id] = {
  createdAt,
  kekVersion: version,
  sealed,
  createdByUserId: user.userId,
  createdByUsername: user.username
};

// ----------------------------
// INBOX: list messages decryptable by this user
// GET /api/inbox
// ----------------------------
app.get("/api/inbox", requireAuth, (req, res) => {
  const { org, user } = req.qm;

  const items = [];
  const ids = Object.keys(org.messages || {});

  // newest first
  ids.sort((a, b) => {
    const aa = Date.parse(org.messages[a]?.createdAt || "") || 0;
    const bb = Date.parse(org.messages[b]?.createdAt || "") || 0;
    return bb - aa;
  });

  for (const id of ids) {
    const rec = org.messages[id];
    if (!rec) continue;

    // open sealed record
    ensureKeyring(org);
    const kv = String(rec.kekVersion || org.keyring.active);
    const kk = getKekByVersion(org, kv);
    if (!kk) continue;

    let msg;
    try {
      msg = openWithKek(kk.kekBytes, rec.sealed);
    } catch {
      continue;
    }

    // Only show messages where this user has a wrapped key
    const hasKey = !!msg?.wrappedKeys?.[user.userId];
    if (!hasKey) continue;

    const attCount = Array.isArray(msg.attachments) ? msg.attachments.length : 0;
    const attBytes = Array.isArray(msg.attachments)
      ? msg.attachments.reduce((s, a) => s + Number(a?.size || 0), 0)
      : 0;

    items.push({
      id,
      createdAt: rec.createdAt,
      from: rec.createdByUsername || null,
      fromUserId: rec.createdByUserId || null,
      attachmentCount: attCount,
      attachmentsTotalBytes: attBytes
    });
  }

  res.json({ items });
});

  audit(req, orgId, user.userId, "encrypt_store", {
    msgId: id,
    kekVersion: version,
    attachmentCount: attachmentsArr.length,
    attachmentsTotalBytes
  });

  saveData();

  const base = getPublicBase(req);
  const url = `${base}/m/${id}`;
  res.json({ id, url, kekVersion: version });
});

app.get("/api/messages/:id", requireAuth, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user } = req.qm;

  const id = req.params.id;
  const rec = org.messages[id];
  if (!rec) return res.status(404).json({ error: "Not found" });

  ensureKeyring(org);
  const kv = String(rec.kekVersion || org.keyring.active);
  const kk = getKekByVersion(org, kv);
  if (!kk) return res.status(500).json({ error: "Missing KEK for stored message" });

  let msg;
  try {
    msg = openWithKek(kk.kekBytes, rec.sealed);
  } catch {
    return res.status(500).json({ error: "Failed to open message record (bad KEK)" });
  }

  const wrappedDek = msg.wrappedKeys?.[user.userId];
  if (!wrappedDek) {
    audit(req, orgId, user.userId, "decrypt_denied", { msgId: id, reason: "missing_wrapped_key" });
    return res.status(403).json({ error: "No wrapped key for this user" });
  }

  audit(req, orgId, user.userId, "decrypt_payload", { msgId: id, kekVersion: kv });

  res.json({
    id,
    createdAt: rec.createdAt,
    iv: msg.iv,
    ciphertext: msg.ciphertext,
    aad: msg.aad,
    wrappedDek,
    kekVersion: kv,
    attachments: Array.isArray(msg.attachments) ? msg.attachments : []
  });
});

// ----------------------------
// Portal static + routes
// ----------------------------
app.use("/portal", express.static(portalDir, { extensions: ["html"], etag: false, maxAge: 0 }));

app.get("/m/:id", (_req, res) => {
  res.sendFile(path.join(portalDir, "decrypt.html"));
});

app.get("/portal/m/:id", (req, res) => res.redirect(`/m/${req.params.id}`));
app.get("/", (_req, res) => res.redirect("/portal/admin.html"));

const PORT = process.env.PORT || 5173;
app.listen(PORT, () => console.log(`QuantumMail server running on port ${PORT}`));
