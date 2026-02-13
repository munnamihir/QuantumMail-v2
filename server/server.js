import express from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { nanoid } from "nanoid";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
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
    if (!fs.existsSync(dataPath)) {
      return { orgs: {} };
    }
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
function nowIso() {
  return new Date().toISOString();
}

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
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function b64urlDecodeToString(s) {
  const str = String(s || "");
  const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + pad;
  return Buffer.from(b64, "base64").toString("utf8");
}

function bytesToB64(buf) {
  return Buffer.from(buf).toString("base64");
}

function b64ToBytes(b64) {
  return Buffer.from(String(b64 || ""), "base64");
}

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
// Codespaces public base URL helper
// ----------------------------
function getPublicBase(req) {
  const proto = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
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
  if (org.audit.length > 1000) org.audit.length = 1000;
  saveData();
}

// ----------------------------
// KEK keyring (server-side at-rest encryption)
// ----------------------------
function randomKey32() {
  return crypto.randomBytes(32); // 256-bit
}

// Seal/unseal JSON object using AES-256-GCM with KEK.
// This protects stored message records in data.json
function sealWithKek(kekBytes, obj) {
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from("quantummail:kek:v1", "utf8");

  const cipher = crypto.createCipheriv("aes-256-gcm", kekBytes, iv);
  cipher.setAAD(aad);

  const pt = Buffer.from(JSON.stringify(obj), "utf8");
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    ivB64: bytesToB64(iv),
    ctB64: bytesToB64(ct),
    tagB64: bytesToB64(tag)
  };
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
  return { version: v, kekBytes: b64ToBytes(k.kekB64) };
}

function getKekByVersion(org, version) {
  ensureKeyring(org);
  const v = String(version);
  const k = org.keyring.keys[v];
  if (!k) return null;
  return { version: v, kekBytes: b64ToBytes(k.kekB64), meta: k };
}

// ----------------------------
// Org storage
// ----------------------------
function getOrg(orgId) {
  const oid = String(orgId || "").trim();
  if (!oid) return null;

  if (!DB.orgs[oid]) {
    DB.orgs[oid] = {
      users: [],
      audit: [],
      // message record format:
      // messages[id] = { createdAt, kekVersion, sealed:{ivB64,ctB64,tagB64} }
      messages: {},
      keyring: null
    };
  }

  const org = DB.orgs[oid];
  if (!org.users) org.users = [];
  if (!org.audit) org.audit = [];
  if (!org.messages) org.messages = {};
  ensureKeyring(org);

  saveData();
  return org;
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
// Disable caching for portal + /m routes
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

// DEV/ADMIN: create admin with custom username/password (first-time setup)
// POST /dev/create-admin  { orgId, username, password }
app.post("/dev/create-admin", (req, res) => {
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
    createdAt: nowIso()
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

  const org = getOrg(orgId);
  if (!orgId || !org) return res.status(400).json({ error: "Invalid orgId" });

  const user = org.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
  if (!user) return res.status(401).json({ error: "Invalid creds" });

  const ph = sha256(password);
  if (!timingSafeEq(ph, user.passwordHash)) return res.status(401).json({ error: "Invalid creds" });

  const payload = {
    userId: user.userId,
    orgId,
    role: user.role,
    username: user.username,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60
  };

  const token = signToken(payload);
  audit(req, orgId, user.userId, "login", { username: user.username, role: user.role });

  res.json({
    token,
    user: {
      userId: user.userId,
      orgId,
      username: user.username,
      role: user.role,
      status: user.status || "Active",
      hasPublicKey: !!user.publicKeySpkiB64
    }
  });
});

// ----------------------------
// ORG: register public key (extension calls this after login)
// ----------------------------
app.post("/org/register-key", requireAuth, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { user } = req.qm;

  const publicKeySpkiB64 = String(req.body?.publicKeySpkiB64 || "").trim();
  if (!publicKeySpkiB64) return res.status(400).json({ error: "publicKeySpkiB64 required" });

  user.publicKeySpkiB64 = publicKeySpkiB64;
  audit(req, orgId, user.userId, "pubkey_register", { username: user.username });
  saveData();

  res.json({ ok: true });
});

// Back-compat alias some extension builds may call
app.post("/pubkey_register", requireAuth, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { user } = req.qm;

  const publicKeySpkiB64 = String(req.body?.publicKeySpkiB64 || "").trim();
  if (!publicKeySpkiB64) return res.status(400).json({ error: "publicKeySpkiB64 required" });

  user.publicKeySpkiB64 = publicKeySpkiB64;
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
      hasPublicKey: !!u.publicKeySpkiB64
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
    createdAt: nowIso()
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

// ADMIN: delete a user
app.delete("/admin/users/:userId", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user: admin } = req.qm;

  const targetId = String(req.params.userId || "").trim();
  if (!targetId) return res.status(400).json({ error: "userId required" });

  // Prevent deleting yourself (optional but recommended)
  if (targetId === admin.userId) {
    return res.status(400).json({ error: "You cannot delete your own admin account." });
  }

  const idx = org.users.findIndex((u) => u.userId === targetId);
  if (idx < 0) return res.status(404).json({ error: "User not found" });

  // Remove wrapped keys for that user from stored messages (optional cleanup)
  for (const mid of Object.keys(org.messages || {})) {
    try {
      const rec = org.messages[mid];
      const kv = String(rec.kekVersion || org.keyring.active);
      const kk = getKekByVersion(org, kv);
      if (!kk) continue;

      const msg = openWithKek(kk.kekBytes, rec.sealed);
      if (msg?.wrappedKeys && msg.wrappedKeys[targetId]) {
        delete msg.wrappedKeys[targetId];
        // re-seal message
        rec.sealed = sealWithKek(kk.kekBytes, msg);
      }
    } catch {
      // ignore failures; we still delete user
    }
  }

  const removed = org.users.splice(idx, 1)[0];
  audit(req, orgId, admin.userId, "delete_user", { deletedUserId: targetId, username: removed.username });
  saveData();

  res.json({ ok: true, deletedUserId: targetId });
});


// ADMIN: clear a user's registered public key (forces re-register on next login)
app.post("/admin/users/:userId/clear-key", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user: admin } = req.qm;

  const targetId = String(req.params.userId || "").trim();
  if (!targetId) return res.status(400).json({ error: "userId required" });

  const user = org.users.find((u) => u.userId === targetId);
  if (!user) return res.status(404).json({ error: "User not found" });

  user.publicKeySpkiB64 = null;
  audit(req, orgId, admin.userId, "clear_user_pubkey", { targetUserId: targetId, username: user.username });
  saveData();

  res.json({ ok: true });
});


// ----------------------------
// ADMIN: audit
// ----------------------------
app.get("/admin/audit", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const limit = Math.min(parseInt(req.query.limit || "200", 10) || 200, 1000);
  const items = req.qm.org.audit.slice(0, limit);
  res.json({ orgId, items });
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

app.post("/admin/keys/:version/retire", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const org = req.qm.org;
  const adminId = req.qm.user.userId;

  ensureKeyring(org);

  const v = String(req.params.version);
  if (v === String(org.keyring.active)) {
    return res.status(400).json({ error: "Cannot retire active key. Rotate first." });
  }

  const k = org.keyring.keys[v];
  if (!k) return res.status(404).json({ error: "Key version not found" });

  k.status = "retired";
  k.retiredAt = nowIso();

  audit(req, orgId, adminId, "kek_retire", { version: v });
  saveData();

  res.json({ ok: true, retired: v });
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

  const id = nanoid(10);
  const createdAt = nowIso();

  const { version, kekBytes } = getActiveKek(org);

if (payload.attachments != null && !Array.isArray(payload.attachments)) {
  return res.status(400).json({ error: "attachments must be an array" });
}


  const sealed = sealWithKek(kekBytes, {
  iv: payload.iv,
  ciphertext: payload.ciphertext,
  aad: payload.aad || "gmail",
  wrappedKeys: payload.wrappedKeys,

  // ✅ NEW: encrypted attachments (already AES-GCM under same DEK)
  attachments: Array.isArray(payload.attachments) ? payload.attachments : []
});


  org.messages[id] = {
    createdAt,
    kekVersion: version,
    sealed
  };

  audit(req, orgId, user.userId, "encrypt_store", { msgId: id, kekVersion: version });
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
    audit(req, orgId, user.userId, "decrypt_denied", { msgId: id });
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

  // ✅ NEW: return encrypted attachments
  attachments: Array.isArray(msg.attachments) ? msg.attachments : []
});

});

// ----------------------------
// Portal static + decrypt route
// ----------------------------
app.use("/portal", express.static(portalDir, { extensions: ["html"], etag: false, maxAge: 0 }));

// Canonical decrypt URL
app.get("/m/:id", (_req, res) => {
  res.sendFile(path.join(portalDir, "decrypt.html"));
});

// Back-compat: if something generates /portal/m/<id>, redirect to /m/<id>
app.get("/portal/m/:id", (req, res) => res.redirect(`/m/${req.params.id}`));

app.get("/", (_req, res) => res.redirect("/portal/compose.html"));

const PORT = process.env.PORT || 5173;
app.listen(PORT, () => {
  console.log(`QuantumMail server running on port ${PORT}`);
});
