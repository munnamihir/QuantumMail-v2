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

/* =========================================================
   Required env in production (no placeholders)
========================================================= */
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";

const TOKEN_SECRET = process.env.QM_TOKEN_SECRET;
if (IS_PROD && (!TOKEN_SECRET || TOKEN_SECRET.length < 32)) {
  throw new Error("QM_TOKEN_SECRET is required in production and must be >= 32 chars.");
}

// optional (recommended)
const QM_EXTENSION_ID = process.env.QM_EXTENSION_ID || "";
if (IS_PROD && !QM_EXTENSION_ID) {
  throw new Error("QM_EXTENSION_ID is required in production (your Chrome extension id).");
}

const ALLOWED_WEB_ORIGINS = (process.env.QM_ALLOWED_WEB_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

/* =========================================================
   CORS (strict)
========================================================= */
function isAllowedOrigin(origin) {
  if (!origin) return true; // curl/server-to-server

  // Allow chrome extension origin only if configured
  if (QM_EXTENSION_ID && origin === `chrome-extension://${QM_EXTENSION_ID}`) return true;

  // Allow configured web origins only (no hardcoded)
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

app.options("*", cors());
app.use(express.json({ limit: "25mb" }));

/* =========================================================
   Paths + persistence
========================================================= */
const portalDir = path.join(__dirname, "..", "portal");
const dataPath = path.join(__dirname, "data.json");

function loadData() {
  try {
    if (!fs.existsSync(dataPath)) return { orgs: {} };
    return JSON.parse(fs.readFileSync(dataPath, "utf8"));
  } catch {
    return { orgs: {} };
  }
}

const DB = loadData();
if (!DB.orgs) DB.orgs = {};

function saveData() {
  fs.writeFileSync(dataPath, JSON.stringify(DB, null, 2), "utf8");
}

/* =========================================================
   Helpers
========================================================= */
function nowIso() { return new Date().toISOString(); }

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

function getPublicBase(req) {
  const proto = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
}

/* =========================================================
   Password hashing (SECURE): scrypt + per-user salt
========================================================= */
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 64); // 64 bytes derived key
  return `scrypt$${salt.toString("base64")}$${key.toString("base64")}`;
}

function verifyPassword(password, stored) {
  const s = String(stored || "");
  const parts = s.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;

  const salt = Buffer.from(parts[1], "base64");
  const expected = Buffer.from(parts[2], "base64");
  const key = crypto.scryptSync(password, salt, expected.length);

  return timingSafeEq(key.toString("base64"), expected.toString("base64"));
}

/* =========================================================
   Token (HMAC) - minimal JWT-like
========================================================= */
function signToken(payload) {
  if (!TOKEN_SECRET) throw new Error("QM_TOKEN_SECRET missing.");
  const header = { alg: "HS256", typ: "JWT" };
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", TOKEN_SECRET).update(`${h}.${p}`).digest();
  const s = b64urlEncode(sig);
  return `${h}.${p}.${s}`;
}

function verifyToken(token) {
  if (!TOKEN_SECRET) return null;
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

/* =========================================================
   Org model
========================================================= */
function defaultPolicies() {
  return {
    forceAttachmentEncryption: false,
    disablePassphraseMode: false,
    enforceKeyRotationDays: 0,
    requireReauthForDecrypt: true
  };
}

function peekOrg(orgId) {
  const oid = String(orgId || "").trim();
  if (!oid) return null;
  return DB.orgs?.[oid] || null;
}

function ensureKeyring(org) {
  if (!org.keyring) {
    const kek = crypto.randomBytes(32);
    org.keyring = {
      active: "1",
      keys: {
        "1": {
          version: "1",
          status: "active",
          createdAt: nowIso(),
          activatedAt: nowIso(),
          retiredAt: null,
          kekB64: kek.toString("base64")
        }
      }
    };
  }
}

function getOrg(orgId) {
  const oid = String(orgId || "").trim();
  if (!oid) return null;

  if (!DB.orgs[oid]) {
    DB.orgs[oid] = {
      users: [],
      audit: [],
      messages: {},
      policies: defaultPolicies(),
      invites: {},
      keyring: null
    };
  }

  const org = DB.orgs[oid];
  if (!org.users) org.users = [];
  if (!org.audit) org.audit = [];
  if (!org.messages) org.messages = {};
  if (!org.invites) org.invites = {};
  if (!org.policies) org.policies = defaultPolicies();
  ensureKeyring(org);

  saveData();
  return org;
}

/* =========================================================
   Audit
========================================================= */
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

/* =========================================================
   KEK sealing (at-rest)
========================================================= */
function sealWithKek(kekBytes, obj) {
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from("quantummail:kek:v1", "utf8");

  const cipher = crypto.createCipheriv("aes-256-gcm", kekBytes, iv);
  cipher.setAAD(aad);

  const pt = Buffer.from(JSON.stringify(obj), "utf8");
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    ivB64: iv.toString("base64"),
    ctB64: ct.toString("base64"),
    tagB64: tag.toString("base64"),
  };
}

function openWithKek(kekBytes, sealed) {
  const iv = Buffer.from(sealed.ivB64, "base64");
  const ct = Buffer.from(sealed.ctB64, "base64");
  const tag = Buffer.from(sealed.tagB64, "base64");
  const aad = Buffer.from("quantummail:kek:v1", "utf8");

  const decipher = crypto.createDecipheriv("aes-256-gcm", kekBytes, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);

  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return JSON.parse(pt.toString("utf8"));
}

function getActiveKek(org) {
  ensureKeyring(org);
  const v = String(org.keyring.active);
  const k = org.keyring.keys[v];
  return { version: v, kekBytes: Buffer.from(k.kekB64, "base64"), meta: k };
}
function getKekByVersion(org, version) {
  ensureKeyring(org);
  const v = String(version);
  const k = org.keyring.keys[v];
  if (!k) return null;
  return { version: v, kekBytes: Buffer.from(k.kekB64, "base64"), meta: k };
}

/* =========================================================
   Auth middleware
========================================================= */
function requireAuth(req, res, next) {
  const auth = String(req.headers.authorization || "");
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: "Missing Bearer token" });

  const payload = verifyToken(m[1]);
  if (!payload) return res.status(401).json({ error: "Invalid/expired token" });

  const org = getOrg(payload.orgId);
  if (!org) return res.status(401).json({ error: "Unknown org" });

  const user = org.users.find(u => u.userId === payload.userId);
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

/* =========================================================
   Simple rate limiter (in-memory)
========================================================= */
const RATE = new Map(); // key -> { count, resetAt }
function rateLimit({ keyFn, limit, windowMs }) {
  return (req, res, next) => {
    const key = keyFn(req);
    const now = Date.now();
    const cur = RATE.get(key);

    if (!cur || now > cur.resetAt) {
      RATE.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }

    cur.count++;
    if (cur.count > limit) {
      return res.status(429).json({ error: "Too many requests. Try again later." });
    }

    next();
  };
}

const authLimiter = rateLimit({
  keyFn: (req) => `${req.ip}|auth`,
  limit: 20,
  windowMs: 10 * 60 * 1000
});

/* =========================================================
   No-cache for portal + /m
========================================================= */
app.use((req, res, next) => {
  if (req.path.startsWith("/portal") || req.path.startsWith("/m/")) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("Surrogate-Control", "no-store");
  }
  next();
});

/* =========================================================
   ORG: checks (peek-only)
========================================================= */
app.get("/org/check", (req, res) => {
  const orgId = String(req.query.orgId || "").trim();
  if (!orgId) return res.status(400).json({ error: "orgId required" });

  const org = peekOrg(orgId);
  const exists = !!org;
  const userCount = exists ? (org.users?.length || 0) : 0;
  const hasAdmin = exists ? !!(org.users || []).find(u => u.role === "Admin") : false;

  res.json({ ok: true, orgId, exists, initialized: exists && hasAdmin, userCount, hasAdmin });
});

app.get("/org/check-username", (req, res) => {
  const orgId = String(req.query.orgId || "").trim();
  const username = String(req.query.username || "").trim();
  if (!orgId || !username) return res.status(400).json({ error: "orgId and username required" });

  const org = peekOrg(orgId);
  if (!org) return res.json({ ok: true, orgId, username, orgExists: false, available: false });

  const taken = !!(org.users || []).find(u => String(u.username || "").toLowerCase() === username.toLowerCase());
  res.json({ ok: true, orgId, username, orgExists: true, available: !taken });
});

/* =========================================================
   DEV: seed admin (ONLY enable in dev)
========================================================= */
app.post("/dev/seed-admin", (req, res) => {
  if (IS_PROD) return res.status(403).json({ error: "Disabled in production" });

  const orgId = String(req.body?.orgId || "").trim();
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");

  if (!orgId || !username || !password) return res.status(400).json({ error: "orgId, username, password required" });
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });

  const org = getOrg(orgId);
  const exists = org.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (exists) return res.status(409).json({ error: "Username already exists" });

  const admin = {
    userId: nanoid(10),
    username,
    passwordHash: hashPassword(password),
    role: "Admin",
    status: "Active",
    publicKeySpkiB64: null,
    publicKeyRegisteredAt: null,
    createdAt: nowIso(),
    lastLoginAt: null
  };

  org.users.push(admin);
  audit(req, orgId, admin.userId, "create_admin", { username });
  saveData();
  res.json({ ok: true, orgId, userId: admin.userId, username });
});

/* =========================================================
   AUTH: signup
========================================================= */
app.post("/auth/signup", authLimiter, (req, res) => {
  const signupType = String(req.body?.signupType || "Individual");
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  let orgId = String(req.body?.orgId || "").trim();
  const inviteCode = String(req.body?.inviteCode || "").trim();
  const wantAdmin = !!req.body?.wantAdmin;

  if (!username || !password) return res.status(400).json({ error: "username and password required" });
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });

  if (signupType === "Individual") {
    if (!orgId) orgId = `org_${nanoid(10)}`;

    const org = getOrg(orgId);

    const exists = org.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (exists) return res.status(409).json({ error: "Username already exists" });

    const role = wantAdmin ? "Admin" : "Member";
    const newUser = {
      userId: nanoid(10),
      username,
      passwordHash: hashPassword(password),
      role,
      status: "Active",
      publicKeySpkiB64: null,
      publicKeyRegisteredAt: null,
      createdAt: nowIso(),
      lastLoginAt: null
    };

    org.users.push(newUser);
    audit(req, orgId, newUser.userId, "signup", { username, role, signupType });
    saveData();
    return res.json({ ok: true, orgId, role });
  }

  if (signupType === "OrgType") {
    if (!orgId) return res.status(400).json({ error: "orgId required for OrgType signup" });
    if (!inviteCode) return res.status(400).json({ error: "inviteCode required for OrgType signup" });

    const org = getOrg(orgId);

    const hasAdmin = !!(org.users || []).find(u => u.role === "Admin");
    if (!hasAdmin) return res.status(400).json({ error: "Organization not initialized yet. Admin must initialize first." });

    const inv = org.invites?.[inviteCode];
    if (!inv) return res.status(403).json({ error: "Invalid invite code" });
    if (inv.usedAt) return res.status(403).json({ error: "Invite code already used" });

    const exp = Date.parse(inv.expiresAt || "");
    if (!Number.isNaN(exp) && Date.now() > exp) return res.status(403).json({ error: "Invite code expired" });

    const exists = org.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (exists) return res.status(409).json({ error: "Username already exists" });

    const role = inv.role === "Admin" ? "Admin" : "Member";

    const newUser = {
      userId: nanoid(10),
      username,
      passwordHash: hashPassword(password),
      role,
      status: "Active",
      publicKeySpkiB64: null,
      publicKeyRegisteredAt: null,
      createdAt: nowIso(),
      lastLoginAt: null
    };

    org.users.push(newUser);
    inv.usedAt = nowIso();
    inv.usedByUserId = newUser.userId;

    audit(req, orgId, newUser.userId, "signup", { username, role, signupType, inviteCode });
    saveData();
    return res.json({ ok: true, orgId, role });
  }

  return res.status(400).json({ error: "Invalid signupType" });
});

/* =========================================================
   AUTH: login/me/change-password
========================================================= */
app.post("/auth/login", authLimiter, (req, res) => {
  const orgId = String(req.body?.orgId || "").trim();
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");

  if (!orgId || !username || !password) return res.status(400).json({ error: "orgId, username, password required" });

  const org = getOrg(orgId);
  const user = org.users.find(u => u.username.toLowerCase() === username.toLowerCase());

  if (!user) {
    audit(req, orgId, null, "login_failed", { username, reason: "unknown_user" });
    return res.status(401).json({ error: "Invalid creds" });
  }

  if (!verifyPassword(password, user.passwordHash)) {
    audit(req, orgId, user.userId, "login_failed", { username: user.username, reason: "bad_password" });
    return res.status(401).json({ error: "Invalid creds" });
  }

  user.lastLoginAt = nowIso();

  const payload = {
    jti: nanoid(12),
    userId: user.userId,
    orgId,
    role: user.role,
    username: user.username,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60
  };

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

app.get("/auth/me", requireAuth, (req, res) => {
  const { user } = req.qm;
  res.json({
    ok: true,
    user: {
      userId: user.userId,
      orgId: req.qm.tokenPayload.orgId,
      username: user.username,
      role: user.role,
      status: user.status || "Active"
    }
  });
});

app.post("/auth/change-password", requireAuth, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { user } = req.qm;

  const currentPassword = String(req.body?.currentPassword || "");
  const newPassword = String(req.body?.newPassword || "");

  if (!currentPassword || !newPassword) return res.status(400).json({ error: "currentPassword and newPassword required" });
  if (newPassword.length < 8) return res.status(400).json({ error: "New password must be at least 8 characters" });

  if (!verifyPassword(currentPassword, user.passwordHash)) {
    audit(req, orgId, user.userId, "change_password_failed", { reason: "bad_current_password" });
    return res.status(401).json({ error: "Current password is incorrect" });
  }

  // prevent same password reuse (best-effort)
  if (verifyPassword(newPassword, user.passwordHash)) {
    return res.status(400).json({ error: "New password must be different" });
  }

  user.passwordHash = hashPassword(newPassword);
  audit(req, orgId, user.userId, "change_password", { username: user.username, role: user.role });
  saveData();

  res.json({ ok: true });
});

/* =========================================================
   ORG: register key + list users
========================================================= */
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

app.get("/org/users", requireAuth, (req, res) => {
  const { org } = req.qm;
  res.json({
    users: org.users.map(u => ({
      userId: u.userId,
      username: u.username,
      role: u.role,
      status: u.status || "Active",
      publicKeySpkiB64: u.publicKeySpkiB64 || null,
      hasPublicKey: !!u.publicKeySpkiB64
    }))
  });
});

/* =========================================================
   ADMIN: invites + users (keeping your existing endpoints)
========================================================= */
function genInviteCode() {
  const n = crypto.randomInt(0, 1000000);
  const s = String(n).padStart(6, "0");
  return `${s.slice(0,3)}-${s.slice(3)}`;
}

app.post("/admin/invites/generate", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user: admin } = req.qm;

  const role = String(req.body?.role || "Member") === "Admin" ? "Admin" : "Member";
  const expiresMinutes = Math.min(Math.max(parseInt(req.body?.expiresMinutes || "60", 10) || 60, 5), 7 * 24 * 60);

  let code;
  for (let i = 0; i < 5; i++) {
    code = genInviteCode();
    if (!org.invites[code]) break;
  }
  if (!code || org.invites[code]) return res.status(500).json({ error: "Could not generate code" });

  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + expiresMinutes * 60 * 1000).toISOString();

  org.invites[code] = { code, role, createdAt, expiresAt, createdByUserId: admin.userId, usedAt: null, usedByUserId: null };
  audit(req, orgId, admin.userId, "invite_generate", { code, role, expiresAt });
  saveData();

  res.json({ ok: true, code, role, expiresAt });
});

app.get("/admin/invites", requireAuth, requireAdmin, (req, res) => {
  const { org } = req.qm;
  const items = Object.values(org.invites || {})
    .sort((a,b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
    .slice(0, 50);
  res.json({ items });
});

app.get("/admin/users", requireAuth, requireAdmin, (req, res) => {
  const { org } = req.qm;
  res.json({
    users: org.users.map(u => ({
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
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });

  const exists = org.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (exists) return res.status(409).json({ error: "Username already exists" });

  const newUser = {
    userId: nanoid(10),
    username,
    passwordHash: hashPassword(password),
    role: role === "Admin" ? "Admin" : "Member",
    status: "Active",
    publicKeySpkiB64: null,
    publicKeyRegisteredAt: null,
    createdAt: nowIso(),
    lastLoginAt: null
  };

  org.users.push(newUser);
  audit(req, orgId, admin.userId, "create_user", { createdUserId: newUser.userId, username: newUser.username, role: newUser.role });
  saveData();

  res.json({ ok: true, userId: newUser.userId });
});

app.delete("/admin/users/:userId", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user: admin } = req.qm;

  const targetId = String(req.params.userId || "").trim();
  if (!targetId) return res.status(400).json({ error: "userId required" });
  if (targetId === admin.userId) return res.status(400).json({ error: "You cannot delete your own admin account." });

  const idx = org.users.findIndex(u => u.userId === targetId);
  if (idx < 0) return res.status(404).json({ error: "User not found" });

  // cleanup wrapped keys
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
    } catch {}
  }

  const removed = org.users.splice(idx, 1)[0];
  audit(req, orgId, admin.userId, "delete_user", { deletedUserId: targetId, username: removed.username });
  saveData();
  res.json({ ok: true, deletedUserId: targetId });
});

app.post("/admin/users/:userId/clear-key", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user: admin } = req.qm;

  const targetId = String(req.params.userId || "").trim();
  if (!targetId) return res.status(400).json({ error: "userId required" });

  const u = org.users.find(x => x.userId === targetId);
  if (!u) return res.status(404).json({ error: "User not found" });

  u.publicKeySpkiB64 = null;
  u.publicKeyRegisteredAt = null;
  audit(req, orgId, admin.userId, "clear_user_pubkey", { targetUserId: targetId, username: u.username });
  saveData();

  res.json({ ok: true });
});

/* =========================================================
   MESSAGES + INBOX
========================================================= */
app.post("/api/messages", requireAuth, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user } = req.qm;

  const payload = req.body || {};
  if (!payload.iv || !payload.ciphertext || !payload.wrappedKeys) {
    return res.status(400).json({ error: "Invalid payload (iv, ciphertext, wrappedKeys required)" });
  }

  const attachmentsArr = Array.isArray(payload.attachments) ? payload.attachments : [];
  const attachmentsTotalBytes = attachmentsArr.reduce((sum, a) => sum + Number(a?.size || 0), 0);

  const id = nanoid(10);
  const createdAt = nowIso();

  const { version, kekBytes } = getActiveKek(org);

  const sealed = sealWithKek(kekBytes, {
    iv: payload.iv,
    ciphertext: payload.ciphertext,
    aad: payload.aad || "gmail",
    wrappedKeys: payload.wrappedKeys,
    attachments: attachmentsArr
  });

  org.messages[id] = {
    createdAt,
    kekVersion: version,
    sealed,
    createdByUserId: user.userId,
    createdByUsername: user.username
  };

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

app.get("/api/inbox", requireAuth, (req, res) => {
  const { org, user } = req.qm;

  const ids = Object.keys(org.messages || {});
  ids.sort((a,b) => (Date.parse(org.messages[b]?.createdAt || "") || 0) - (Date.parse(org.messages[a]?.createdAt || "") || 0));

  const items = [];

  for (const id of ids) {
    const rec = org.messages[id];
    if (!rec) continue;

    const kv = String(rec.kekVersion || org.keyring.active);
    const kk = getKekByVersion(org, kv);
    if (!kk) continue;

    let msg;
    try { msg = openWithKek(kk.kekBytes, rec.sealed); } catch { continue; }

    if (!msg?.wrappedKeys?.[user.userId]) continue;

    const attCount = Array.isArray(msg.attachments) ? msg.attachments.length : 0;
    const attBytes = Array.isArray(msg.attachments) ? msg.attachments.reduce((s,a)=> s + Number(a?.size||0), 0) : 0;

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

app.get("/api/messages/:id", requireAuth, (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user } = req.qm;

  const id = String(req.params.id || "").trim();
  const rec = org.messages[id];
  if (!rec) return res.status(404).json({ error: "Not found" });

  const kv = String(rec.kekVersion || org.keyring.active);
  const kk = getKekByVersion(org, kv);
  if (!kk) return res.status(500).json({ error: "Missing KEK for stored message" });

  let msg;
  try { msg = openWithKek(kk.kekBytes, rec.sealed); }
  catch { return res.status(500).json({ error: "Failed to open message record" }); }

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

/* =========================================================
   Static portal routes
========================================================= */
app.use("/portal", express.static(portalDir, { extensions: ["html"], etag: false, maxAge: 0 }));

app.get("/m/:id", (_req, res) => res.sendFile(path.join(portalDir, "decrypt.html")));
app.get("/portal/m/:id", (req, res) => res.redirect(`/m/${req.params.id}`));
app.get("/", (_req, res) => res.redirect("/portal/index.html"));

/* =========================================================
   Start
========================================================= */
const PORT = process.env.PORT || 5173;
app.listen(PORT, () => console.log(`QuantumMail server running on port ${PORT}`));
