import express from "express";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { nanoid } from "nanoid";
import cors from "cors";

import { pool } from "./db.js";                 // ✅ required (Neon/PG pool)
import { peekOrg, getOrg, saveOrg } from "./orgStore.js";  // ✅ your JSONB org store

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

/* =========================================================
   ENV (Render / Neon)
========================================================= */
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";

const PLATFORM_ORG_ID = process.env.QM_PLATFORM_ORG_ID;
if (!PLATFORM_ORG_ID) throw new Error("QM_PLATFORM_ORG_ID is required.");

const TOKEN_SECRET = process.env.QM_TOKEN_SECRET;
if (!TOKEN_SECRET || TOKEN_SECRET.length < 32) {
  throw new Error("QM_TOKEN_SECRET is required and must be >= 32 chars.");
}

const EXTENSION_ID = process.env.QM_EXTENSION_ID || ""; // optional in dev, recommended in prod

const ALLOWED_WEB_ORIGINS = (process.env.QM_ALLOWED_WEB_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

if (IS_PROD && ALLOWED_WEB_ORIGINS.length === 0) {
  throw new Error("QM_ALLOWED_WEB_ORIGINS is required in production (comma-separated).");
}

const BOOTSTRAP_SECRET = process.env.QM_BOOTSTRAP_SECRET || "";
const BOOTSTRAP_ENABLED = BOOTSTRAP_SECRET.length >= 32;

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

function sha256(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function sha256Hex(s) { return sha256(s); }

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

function getPublicBase(req) {
  const proto = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
}

function defaultPolicies() {
  return {
    forceAttachmentEncryption: false,
    disablePassphraseMode: false,
    enforceKeyRotationDays: 0,
    requireReauthForDecrypt: true,
  };
}

/* =========================================================
   CORS (strict)
========================================================= */
function isAllowedOrigin(origin) {
  if (!origin) return true; // curl/server-to-server
  if (EXTENSION_ID && origin === `chrome-extension://${EXTENSION_ID}`) return true;
  if (ALLOWED_WEB_ORIGINS.includes(origin)) return true;
  return false;
}

app.use(cors({
  origin: (origin, cb) => {
    if (isAllowedOrigin(origin)) return cb(null, true);
    return cb(new Error(`CORS blocked origin: ${origin}`));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-QM-Bootstrap"],
  credentials: false
}));

app.options("*", cors());
app.use(express.json({ limit: "25mb" }));

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
   Token (minimal JWT-like HMAC-SHA256)
========================================================= */
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

/* =========================================================
   Auth middleware (Postgres-backed org)
========================================================= */
async function requireAuth(req, res, next) {
  try {
    const auth = String(req.headers.authorization || "");
    const m = auth.match(/^Bearer\s+(.+)$/i);
    if (!m) return res.status(401).json({ error: "Missing Bearer token" });

    const payload = verifyToken(m[1]);
    if (!payload) return res.status(401).json({ error: "Invalid/expired token" });

    const org = await getOrg(payload.orgId);
    if (!org) return res.status(401).json({ error: "Unknown org" });

    const user = (org.users || []).find((u) => u.userId === payload.userId);
    if (!user) return res.status(401).json({ error: "Unknown user" });

    if (String(user.status || "Active").toLowerCase() === "disabled") {
      return res.status(403).json({ error: "User disabled" });
    }

    req.qm = { tokenPayload: payload, org, user };
    next();
  } catch {
    async function apiJson(serverBase, path, { method = "GET", token = "", body = null } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers["Content-Type"] = "application/json";

  const url = `${serverBase}${path}`;
  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });

  // Read raw once (works even if server returns HTML/text on error)
  const ct = res.headers.get("content-type") || "";
  const raw = await res.text();

  let data = {};
  try {
    data = ct.includes("application/json") ? JSON.parse(raw || "{}") : { raw };
  } catch {
    data = { raw };
  }

  if (!res.ok) {
    console.error("API ERROR:", { url, status: res.status, data, raw });
    throw new Error(data?.error || data?.message || `HTTP ${res.status}: ${String(raw).slice(0, 200)}`);
  }

  return data;
}
  }
}

function requireAdmin(req, res, next) {
  if (!req.qm?.user) return res.status(401).json({ error: "Unauthorized" });
  if (req.qm.user.role !== "Admin") return res.status(403).json({ error: "Admin only" });
  next();
}

function requireSuperAdmin(req, res, next) {
  if (!req.qm?.user) return res.status(401).json({ error: "Unauthorized" });
  if (req.qm.tokenPayload.orgId !== PLATFORM_ORG_ID) {
    return res.status(403).json({ error: "Super admin only (platform org)" });
  }
  if (req.qm.user.role !== "SuperAdmin") {
    return res.status(403).json({ error: "Super admin only" });
  }
  next();
}

/* =========================================================
   Bootstrap protection (header secret)
========================================================= */
function requireBootstrapSecret(req, res, next) {
  if (!BOOTSTRAP_ENABLED) {
    return res.status(503).json({ error: "Bootstrap disabled (QM_BOOTSTRAP_SECRET not set or <32)" });
  }
  const provided = String(req.headers["x-qm-bootstrap"] || "");
  if (!provided) return res.status(401).json({ error: "Missing X-QM-Bootstrap header" });
  if (!timingSafeEq(provided, BOOTSTRAP_SECRET)) return res.status(403).json({ error: "Bootstrap denied" });
  next();
}

// rate limit only bootstrap routes
const RATE = new Map(); // ip -> {count, resetAt}
function rateLimitBootstrap(req, res, next) {
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket?.remoteAddress || "unknown";
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const limit = 10;

  const cur = RATE.get(ip);
  if (!cur || now > cur.resetAt) {
    RATE.set(ip, { count: 1, resetAt: now + windowMs });
    return next();
  }
  cur.count++;
  if (cur.count > limit) return res.status(429).json({ error: "Too many bootstrap attempts" });
  next();
}

/* =========================================================
   Audit (durable via saveOrg)
========================================================= */
async function audit(req, orgId, userId, action, details = {}) {
  const org = await getOrg(orgId);
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

  org.audit = Array.isArray(org.audit) ? org.audit : [];
  org.audit.unshift(entry);
  if (org.audit.length > 2000) org.audit.length = 2000;

  await saveOrg(orgId, org);
}

/* =========================================================
   KEK keyring (server-side at-rest encryption)
========================================================= */
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
  org.keyring = org.keyring || null;
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
          kekB64: bytesToB64(kek),
        },
      },
    };
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

/* =========================================================
   Invite helper
========================================================= */
function genInviteCode() {
  const n = crypto.randomInt(0, 1000000);
  const s = String(n).padStart(6, "0");
  return `${s.slice(0, 3)}-${s.slice(3)}`;
}

/* =========================================================
   DB bootstrap (tables)
========================================================= */
async function ensureTables() {
  await pool.query(`
    create table if not exists qm_org_requests (
      id text primary key,
      org_name text not null,
      requester_name text not null,
      requester_email text not null,
      notes text,
      status text not null default 'pending', -- pending|approved|rejected
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      reviewed_by_user_id text,
      reviewed_at timestamptz,
      reject_reason text,
      approved_org_id text,
      approved_admin_user_id text
    );
  `);

  await pool.query(`
    create table if not exists qm_setup_tokens (
      id text primary key,
      org_id text not null,
      user_id text not null,
      token_hash text not null,
      purpose text not null,
      expires_at timestamptz not null,
      used_at timestamptz,
      created_at timestamptz not null default now()
    );
  `);

  await pool.query(`create index if not exists idx_qm_setup_tokens_org_hash on qm_setup_tokens(org_id, token_hash);`);
  await pool.query(`create index if not exists idx_qm_org_requests_status on qm_org_requests(status, created_at);`);
}
await ensureTables();

// =========================================================
// AUTH: signup via invite code (Member/Admin)
// POST /auth/signup { orgId, inviteCode, username, password }
// =========================================================
app.post("/auth/signup", async (req, res) => {
  const orgId = String(req.body?.orgId || "").trim();
  const inviteCode = String(req.body?.inviteCode || "").trim();
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");

  if (!orgId || !inviteCode || !username || !password) {
    return res.status(400).json({ error: "orgId, inviteCode, username, password required" });
  }
  if (password.length < 12) {
    return res.status(400).json({ error: "Password must be at least 12 characters" });
  }

  const org = await getOrg(orgId);
  org.users = org.users || [];
  org.audit = org.audit || [];
  org.invites = org.invites || {};
  org.policies = org.policies || defaultPolicies();
  ensureKeyring(org);

  const inv = org.invites[inviteCode];
  if (!inv) return res.status(403).json({ error: "Invalid invite code" });

  if (inv.usedAt) return res.status(403).json({ error: "Invite already used" });
  if (Date.parse(inv.expiresAt || "") < Date.now()) return res.status(403).json({ error: "Invite expired" });

  const taken = org.users.some(u => String(u.username || "").toLowerCase() === username.toLowerCase());
  if (taken) return res.status(409).json({ error: "Username already exists" });

  const userId = nanoid(10);
  const role = inv.role === "Admin" ? "Admin" : "Member";

  org.users.push({
    userId,
    username,
    passwordHash: sha256(password),
    role,
    status: "Active",
    publicKeySpkiB64: null,
    publicKeyRegisteredAt: null,
    createdAt: nowIso(),
    lastLoginAt: null
  });

  inv.usedAt = nowIso();
  inv.usedByUserId = userId;

  await audit(req, orgId, userId, "signup_via_invite", { username, role, inviteCode });
  await saveOrg(orgId, org);

  res.json({ ok: true, orgId, userId, username, role });
});


// =========================================================
// ORG: get my org info (for Profile UI)
// GET /org/me
// =========================================================
app.get("/org/me", requireAuth, async (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const org = await getOrg(orgId);

  res.json({
    ok: true,
    org: {
      orgId,
      orgName: org.orgName || org.name || orgId, // fallback
    }
  });
});

// =========================================================
// ADMIN: SECURITY ALERTS
// GET /admin/alerts?minutes=60
// =========================================================
app.get("/admin/alerts", requireAuth, requireAdmin, async (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;

  const minutes = Math.min(
    Math.max(parseInt(req.query.minutes || "60", 10) || 60, 1),
    7 * 24 * 60
  );

  const org = await getOrg(orgId);
  const since = Date.now() - minutes * 60 * 1000;

  const alerts = [];
  const items = Array.isArray(org.audit) ? org.audit : [];

  for (const a of items) {
    const at = Date.parse(a.at || "");
    if (Number.isNaN(at) || at < since) continue;

    if (a.action === "login_failed") {
      alerts.push({
        code: "LOGIN_FAILED",
        severity: "high",
        at: a.at,
        message: `Failed login for ${a.username || "unknown"} from ${a.ip || "unknown ip"}`
      });
    }

    if (a.action === "decrypt_denied") {
      alerts.push({
        code: "DECRYPT_DENIED",
        severity: "critical",
        at: a.at,
        message: `Unauthorized decrypt attempt (msgId=${a.msgId || "?"})`
      });
    }

    if (a.action === "clear_user_pubkey") {
      alerts.push({
        code: "KEY_CLEARED",
        severity: "medium",
        at: a.at,
        message: `Public key cleared for userId=${a.targetUserId || "?"}`
      });
    }
  }

  const summary = {
    denied: alerts.filter(x => x.code === "DECRYPT_DENIED").length,
    failedLogins: alerts.filter(x => x.code === "LOGIN_FAILED").length
  };

  res.json({ ok: true, orgId, minutes, summary, alerts: alerts.slice(0, 200) });
});


// =========================================================
// ADMIN: AUDIT
// GET /admin/audit?limit=200
// =========================================================
app.get("/admin/audit", requireAuth, requireAdmin, async (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const org = await getOrg(orgId);

  const limit = Math.min(
    Math.max(parseInt(req.query.limit || "200", 10) || 200, 10),
    2000
  );

  const items = Array.isArray(org.audit) ? org.audit.slice(0, limit) : [];
  res.json({ ok: true, orgId, items });
});

// =========================================================
// ADMIN: POLICIES
// GET /admin/policies
// POST/PUT /admin/policies
// =========================================================
app.get("/admin/policies", requireAuth, requireAdmin, async (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const org = await getOrg(orgId);

  org.policies = org.policies || defaultPolicies();
  res.json({ ok: true, orgId, policies: org.policies });
});

app.post("/admin/policies", requireAuth, requireAdmin, async (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const org = await getOrg(orgId);

  org.policies = org.policies || defaultPolicies();

  const b = req.body || {};
  org.policies.forceAttachmentEncryption = !!b.forceAttachmentEncryption;
  org.policies.disablePassphraseMode = !!b.disablePassphraseMode;
  org.policies.requireReauthForDecrypt = !!b.requireReauthForDecrypt;
  org.policies.enforceKeyRotationDays = Math.max(0, parseInt(b.enforceKeyRotationDays || "0", 10) || 0);

  await audit(req, orgId, req.qm.user.userId, "policies_update", { policies: org.policies });
  await saveOrg(orgId, org);

  res.json({ ok: true, orgId, policies: org.policies });
});

// optional: PUT alias
app.put("/admin/policies", requireAuth, requireAdmin, async (req, res) => {
  req.method = "POST";
  return app._router.handle(req, res);
});

// =========================================================
// ADMIN: ANALYTICS
// GET /admin/analytics?days=7
// =========================================================
app.get("/admin/analytics", requireAuth, requireAdmin, async (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const org = await getOrg(orgId);

  const days = Math.min(Math.max(parseInt(req.query.days || "7", 10) || 7, 1), 90);
  const since = Date.now() - days * 24 * 60 * 60 * 1000;

  const auditItems = Array.isArray(org.audit) ? org.audit : [];
  const messages = org.messages || {};

  const usersTotal = Array.isArray(org.users) ? org.users.length : 0;
  const messagesTotal = Object.keys(messages).length;

  let encryptStore = 0, decryptPayload = 0, loginFailed = 0, decryptDenied = 0;

  for (const a of auditItems) {
    const at = Date.parse(a.at || "");
    if (Number.isNaN(at) || at < since) continue;

    if (a.action === "encrypt_store") encryptStore++;
    if (a.action === "decrypt_payload") decryptPayload++;
    if (a.action === "login_failed") loginFailed++;
    if (a.action === "decrypt_denied") decryptDenied++;
  }

  res.json({
    ok: true,
    orgId,
    days,
    summary: {
      usersTotal,
      messagesTotal,
      encryptStoreLastNDays: encryptStore,
      decryptPayloadLastNDays: decryptPayload,
      loginFailedLastNDays: loginFailed,
      decryptDeniedLastNDays: decryptDenied
    }
  });
});

/* =========================================================
   ORG: check + check-username (peek-only)
========================================================= */
app.get("/org/check", async (req, res) => {
  const orgId = String(req.query.orgId || "").trim();
  if (!orgId) return res.status(400).json({ error: "orgId required" });

  const org = await peekOrg(orgId);
  const exists = !!org;
  const userCount = exists ? (org.users?.length || 0) : 0;
  const hasAdmin = exists ? !!(org.users || []).find((u) => u.role === "Admin") : false;

  res.json({ ok: true, orgId, exists, initialized: exists && userCount > 0 && hasAdmin, userCount, hasAdmin });
});

app.get("/org/check-username", async (req, res) => {
  const orgId = String(req.query.orgId || "").trim();
  const username = String(req.query.username || "").trim();
  if (!orgId || !username) return res.status(400).json({ error: "orgId and username required" });

  const org = await peekOrg(orgId);
  if (!org) return res.json({ ok: true, orgId, username, orgExists: false, available: false, reason: "org_not_found" });

  const taken = !!(org.users || []).find((u) => String(u.username || "").toLowerCase() === username.toLowerCase());
  res.json({ ok: true, orgId, username, orgExists: true, available: !taken });
});

/* =========================================================
   BOOTSTRAP: create first SuperAdmin in PLATFORM org
   POST /bootstrap/superadmin
   Headers: X-QM-Bootstrap: <QM_BOOTSTRAP_SECRET>
   Body: { username, password } (>=12)
========================================================= */
app.post("/bootstrap/superadmin", rateLimitBootstrap, requireBootstrapSecret, async (req, res) => {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  if (!username || !password || password.length < 12) {
    return res.status(400).json({ error: "username + password (>=12 chars) required" });
  }

  const org = await getOrg(PLATFORM_ORG_ID);
  org.users = org.users || [];
  org.audit = org.audit || [];
  org.policies = org.policies || defaultPolicies();

  const exists = org.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (exists) return res.status(409).json({ error: "User already exists" });

  const userId = nanoid(10);
  org.users.push({
    userId,
    username,
    passwordHash: sha256(password),
    role: "SuperAdmin",
    status: "Active",
    publicKeySpkiB64: null,
    publicKeyRegisteredAt: null,
    createdAt: nowIso(),
    lastLoginAt: null
  });

  org.audit.unshift({ id: nanoid(10), at: nowIso(), action: "bootstrap_superadmin", userId, username });
  await saveOrg(PLATFORM_ORG_ID, org);

  res.json({ ok: true, platformOrgId: PLATFORM_ORG_ID, userId, username });
});

/* =========================================================
   BOOTSTRAP: seed first Admin for an org (allowed in prod, protected)
   POST /dev/seed-admin
   Headers: X-QM-Bootstrap: <QM_BOOTSTRAP_SECRET>
   Body: { orgId, username, password } (>=12)
========================================================= */
app.post("/dev/seed-admin", rateLimitBootstrap, requireBootstrapSecret, async (req, res) => {
  const orgId = String(req.body?.orgId || "").trim();
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");

  if (!orgId || !username || !password) return res.status(400).json({ error: "orgId, username, password required" });
  if (password.length < 12) return res.status(400).json({ error: "Password must be at least 12 characters" });

  const existing = await peekOrg(orgId);
  if (existing) {
    const admins = (existing.users || []).filter(u => u.role === "Admin");
    if (admins.length > 0) {
      return res.status(403).json({ error: "Org already initialized. Use invites or an existing admin." });
    }
  }

  const org = await getOrg(orgId);
  org.users = org.users || [];
  org.audit = org.audit || [];
  org.policies = org.policies || defaultPolicies();
  ensureKeyring(org);

  const taken = org.users.some(u => String(u.username || "").toLowerCase() === username.toLowerCase());
  if (taken) return res.status(409).json({ error: "Username already exists" });

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
  org.audit.unshift({ id: nanoid(10), at: nowIso(), orgId, userId: newAdmin.userId, action: "bootstrap_seed_admin", username });
  if (org.audit.length > 2000) org.audit.length = 2000;

  await saveOrg(orgId, org);
  res.json({ ok: true, orgId, userId: newAdmin.userId, username });
});

/* =========================================================
   PUBLIC: org request
   POST /public/org-requests
   Body: { orgName, requesterName, requesterEmail, notes? }
========================================================= */
app.post("/public/org-requests", async (req, res) => {
  const orgName = String(req.body?.orgName || "").trim();
  const requesterName = String(req.body?.requesterName || "").trim();
  const requesterEmail = String(req.body?.requesterEmail || "").trim();
  const notes = String(req.body?.notes || "").trim();

  if (!orgName || !requesterName || !requesterEmail) {
    return res.status(400).json({ error: "orgName, requesterName, requesterEmail required" });
  }

  const id = nanoid(12);
  await pool.query(
    `insert into qm_org_requests (id, org_name, requester_name, requester_email, notes, status)
     values ($1,$2,$3,$4,$5,'pending')`,
    [id, orgName, requesterName, requesterEmail, notes || null]
  );

  res.json({ ok: true, requestId: id });
});

/* =========================================================
   AUTH: login / me / change-password / setup-admin
========================================================= */
app.post("/auth/login", async (req, res) => {
  const orgId = String(req.body?.orgId || "").trim();
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  if (!orgId || !username || !password) return res.status(400).json({ error: "orgId, username, password required" });

  const org = await getOrg(orgId);
  if (!org || !Array.isArray(org.users)) {
      try { await audit(req, orgId, null, "login_failed", { username, reason: "org_not_found" }); } catch {}
      return res.status(401).json({ error: "Invalid creds" });
    }
   
  const user = (org.users || []).find((u) => u.username.toLowerCase() === username.toLowerCase());
  if (!user) {
    await audit(req, orgId, null, "login_failed", { username, reason: "unknown_user" });
    return res.status(401).json({ error: "Invalid creds" });
  }

  if (String(user.status || "Active") === "PendingSetup") {
    return res.status(403).json({ error: "Account pending setup. Use setup link." });
  }

  const ph = sha256(password);
  if (!user.passwordHash || !timingSafeEq(ph, user.passwordHash)) {
    await audit(req, orgId, user.userId, "login_failed", { username: user.username, reason: "bad_password" });
    return res.status(401).json({ error: "Invalid creds" });
  }

  user.lastLoginAt = nowIso();

  const payload = {
    userId: user.userId,
    orgId,
    role: user.role,
    username: user.username,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60,
  };

  const token = signToken(payload);

  await audit(req, orgId, user.userId, "login", { username: user.username, role: user.role });
  await saveOrg(orgId, org);

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
      publicKeyRegisteredAt: user.publicKeyRegisteredAt,
    },
  });
});

app.get("/auth/me", requireAuth, (req, res) => {
  const { user } = req.qm;
  res.json({ ok: true, user: { userId: user.userId, orgId: req.qm.tokenPayload.orgId, username: user.username, role: user.role, status: user.status || "Active" } });
});

app.post("/auth/change-password", requireAuth, async (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user } = req.qm;

  const currentPassword = String(req.body?.currentPassword || "");
  const newPassword = String(req.body?.newPassword || "");
  if (!currentPassword || !newPassword) return res.status(400).json({ error: "currentPassword and newPassword required" });
  if (newPassword.length < 12) return res.status(400).json({ error: "New password must be at least 12 characters" });

  const curHash = sha256(currentPassword);
  if (!user.passwordHash || !timingSafeEq(curHash, user.passwordHash)) {
    await audit(req, orgId, user.userId, "change_password_failed", { reason: "bad_current_password" });
    return res.status(401).json({ error: "Current password is incorrect" });
  }

  const nextHash = sha256(newPassword);
  if (timingSafeEq(nextHash, user.passwordHash)) return res.status(400).json({ error: "New password must be different" });

  user.passwordHash = nextHash;
  await audit(req, orgId, user.userId, "change_password", { username: user.username, role: user.role });
  await saveOrg(orgId, org);

  res.json({ ok: true });
});

// POST /auth/setup-admin { orgId, token, newPassword }
app.post("/auth/setup-admin", async (req, res) => {
  const orgId = String(req.body?.orgId || "").trim();
  const token = String(req.body?.token || "").trim();
  const newPassword = String(req.body?.newPassword || "");

  if (!orgId || !token || !newPassword) return res.status(400).json({ error: "orgId, token, newPassword required" });
  if (newPassword.length < 12) return res.status(400).json({ error: "Password must be >= 12 characters" });

  const tokenHash = sha256Hex(token);

  const { rows } = await pool.query(
    `select * from qm_setup_tokens
      where org_id=$1 and token_hash=$2 and purpose='initial_admin_setup'`,
    [orgId, tokenHash]
  );
  if (!rows.length) return res.status(403).json({ error: "Invalid token" });

  const t = rows[0];
  if (t.used_at) return res.status(403).json({ error: "Token already used" });
  if (Date.parse(t.expires_at) < Date.now()) return res.status(403).json({ error: "Token expired" });

  const org = await getOrg(orgId);
  const u = (org.users || []).find(x => x.userId === t.user_id);
  if (!u) return res.status(404).json({ error: "User not found" });

  u.passwordHash = sha256(newPassword);
  u.status = "Active";

  await saveOrg(orgId, org);
  await pool.query(`update qm_setup_tokens set used_at=now() where id=$1`, [t.id]);

  res.json({ ok: true });
});

/* =========================================================
   ORG: register key + list users
========================================================= */
app.post("/org/register-key", requireAuth, async (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user } = req.qm;

  const publicKeySpkiB64 = String(req.body?.publicKeySpkiB64 || "").trim();
  if (!publicKeySpkiB64) return res.status(400).json({ error: "publicKeySpkiB64 required" });

  user.publicKeySpkiB64 = publicKeySpkiB64;
  user.publicKeyRegisteredAt = nowIso();

  await audit(req, orgId, user.userId, "pubkey_register", { username: user.username });
  await saveOrg(orgId, org);
  res.json({ ok: true });
});

app.get("/org/users", requireAuth, (req, res) => {
  const { org } = req.qm;
  res.json({
    users: (org.users || []).map((u) => ({
      userId: u.userId,
      username: u.username,
      role: u.role,
      status: u.status || "Active",
      publicKeySpkiB64: u.publicKeySpkiB64 || null,
      hasPublicKey: !!u.publicKeySpkiB64,
    })),
  });
});

/* =========================================================
   ADMIN: invites + users
========================================================= */
app.post("/admin/invites/generate", requireAuth, requireAdmin, async (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user: admin } = req.qm;

  const role = String(req.body?.role || "Member") === "Admin" ? "Admin" : "Member";
  const expiresMinutes = Math.min(Math.max(parseInt(req.body?.expiresMinutes || "60", 10) || 60, 5), 7 * 24 * 60);

  let code;
  for (let i = 0; i < 5; i++) {
    code = genInviteCode();
    if (!org.invites?.[code]) break;
  }

  org.invites = org.invites || {};
  if (!code || org.invites[code]) return res.status(500).json({ error: "Could not generate code" });

  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + expiresMinutes * 60 * 1000).toISOString();

  org.invites[code] = { code, role, createdAt, expiresAt, createdByUserId: admin.userId, usedAt: null, usedByUserId: null };

  await audit(req, orgId, admin.userId, "invite_generate", { code, role, expiresAt });
  await saveOrg(orgId, org);

  res.json({ ok: true, code, role, expiresAt });
});

app.get("/admin/invites", requireAuth, requireAdmin, (req, res) => {
  const { org } = req.qm;
  const items = Object.values(org.invites || {}).sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt)).slice(0, 50);
  res.json({ items });
});

app.get("/admin/users", requireAuth, requireAdmin, (req, res) => {
  const { org } = req.qm;
  res.json({
    users: (org.users || []).map((u) => ({
      userId: u.userId,
      username: u.username,
      role: u.role,
      status: u.status || "Active",
      hasPublicKey: !!u.publicKeySpkiB64,
      lastLoginAt: u.lastLoginAt || null,
      publicKeyRegisteredAt: u.publicKeyRegisteredAt || null,
    })),
  });
});

/* =========================================================
   SUPERADMIN: queue list / approve / reject
========================================================= */
function makeSetupToken() {
  return crypto.randomBytes(32).toString("base64url"); // url-safe
}

app.get("/super/org-requests", requireAuth, requireSuperAdmin, async (req, res) => {
  const status = String(req.query.status || "pending").trim().toLowerCase();
  const allowed = new Set(["pending", "approved", "rejected"]);
  const s = allowed.has(status) ? status : "pending";

  const { rows } = await pool.query(
    `select * from qm_org_requests where status = $1 order by created_at desc limit 200`,
    [s]
  );

  res.json({ ok: true, status: s, items: rows });
});

app.post("/super/org-requests/:id/reject", requireAuth, requireSuperAdmin, async (req, res) => {
  const requestId = String(req.params.id || "").trim();
  const reason = String(req.body?.reason || "").trim();

  const r1 = await pool.query(`select * from qm_org_requests where id=$1`, [requestId]);
  if (!r1.rows.length) return res.status(404).json({ error: "Request not found" });
  if (r1.rows[0].status !== "pending") return res.status(409).json({ error: "Request is not pending" });

  await pool.query(
    `update qm_org_requests
       set status='rejected',
           updated_at=now(),
           reviewed_by_user_id=$2,
           reviewed_at=now(),
           reject_reason=$3
     where id=$1`,
    [requestId, req.qm.user.userId, reason || null]
  );

  res.json({ ok: true });
});

// Approve: create org + create first admin (PendingSetup) + create setup token + return setupLink
app.post("/super/org-requests/:id/approve", requireAuth, requireSuperAdmin, async (req, res) => {
  const requestId = String(req.params.id || "").trim();
  const orgId = String(req.body?.orgId || "").trim();
  const adminUsername = String(req.body?.adminUsername || "").trim();

  if (!requestId || !orgId || !adminUsername) {
    return res.status(400).json({ error: "requestId, orgId, adminUsername required" });
  }

  const r1 = await pool.query(`select * from qm_org_requests where id=$1`, [requestId]);
  if (!r1.rows.length) return res.status(404).json({ error: "Request not found" });
  const reqRow = r1.rows[0];
  if (reqRow.status !== "pending") return res.status(409).json({ error: "Request is not pending" });

  const org = await getOrg(orgId);
  org.users = org.users || [];
  org.audit = org.audit || [];
  org.policies = org.policies || defaultPolicies();
  ensureKeyring(org);

  const taken = org.users.some(u => String(u.username || "").toLowerCase() === adminUsername.toLowerCase());
  if (taken) return res.status(409).json({ error: "adminUsername already exists in org" });

  const adminUserId = nanoid(10);
  org.users.push({
    userId: adminUserId,
    username: adminUsername,
    passwordHash: null,
    role: "Admin",
    status: "PendingSetup",
    publicKeySpkiB64: null,
    publicKeyRegisteredAt: null,
    createdAt: nowIso(),
    lastLoginAt: null
  });

  await saveOrg(orgId, org);

  const rawToken = makeSetupToken();
  const tokenHash = sha256Hex(rawToken);
  const tokenId = nanoid(12);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

  await pool.query(
    `insert into qm_setup_tokens (id, org_id, user_id, token_hash, purpose, expires_at)
     values ($1,$2,$3,$4,'initial_admin_setup',$5)`,
    [tokenId, orgId, adminUserId, tokenHash, expiresAt.toISOString()]
  );

  await pool.query(
    `update qm_org_requests
       set status='approved',
           updated_at=now(),
           reviewed_by_user_id=$2,
           reviewed_at=now(),
           approved_org_id=$3,
           approved_admin_user_id=$4
     where id=$1`,
    [requestId, req.qm.user.userId, orgId, adminUserId]
  );

  const base = getPublicBase(req);
  const setupLink = `${base}/portal/setup-admin.html?orgId=${encodeURIComponent(orgId)}&token=${encodeURIComponent(rawToken)}`;

  res.json({ ok: true, orgId, adminUserId, adminUsername, setupLink, expiresAt: expiresAt.toISOString() });
});

/* =========================================================
   MESSAGES: create + inbox + fetch (durable in org JSON)
========================================================= */
app.post("/api/messages", requireAuth, async (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user } = req.qm;

  const payload = req.body || {};
  if (!payload.iv || !payload.ciphertext || !payload.wrappedKeys) {
    return res.status(400).json({ error: "Invalid payload (iv, ciphertext, wrappedKeys required)" });
  }

  const pol = org.policies || defaultPolicies();
  if (pol.forceAttachmentEncryption) {
    if (payload.attachments != null && !Array.isArray(payload.attachments)) return res.status(400).json({ error: "attachments must be an array" });
    const arr = Array.isArray(payload.attachments) ? payload.attachments : [];
    for (const a of arr) if (!a || !a.iv || !a.ciphertext) return res.status(400).json({ error: "attachments must include iv + ciphertext for each file" });
  }

  const id = nanoid(10);
  const createdAt = nowIso();
  ensureKeyring(org);

  const { version, kekBytes } = getActiveKek(org);

  const attachmentsArr = Array.isArray(payload.attachments) ? payload.attachments : [];
  const attachmentsTotalBytes = attachmentsArr.reduce((sum, a) => sum + Number(a?.size || 0), 0);

  const sealed = sealWithKek(kekBytes, {
    iv: payload.iv,
    ciphertext: payload.ciphertext,
    aad: payload.aad || "gmail",
    wrappedKeys: payload.wrappedKeys,
    attachments: attachmentsArr,
  });

  org.messages = org.messages || {};
  org.messages[id] = {
    createdAt,
    kekVersion: version,
    sealed,
    createdByUserId: user.userId,
    createdByUsername: user.username,
  };

  await audit(req, orgId, user.userId, "encrypt_store", {
    msgId: id,
    kekVersion: version,
    attachmentCount: attachmentsArr.length,
    attachmentsTotalBytes,
  });

  await saveOrg(orgId, org);

  const base = getPublicBase(req);
  const url = `${base}/m/${id}`;
  res.json({ id, url, kekVersion: version });
});

app.get("/api/inbox", requireAuth, (req, res) => {
  const { org, user } = req.qm;

  const items = [];
  const ids = Object.keys(org.messages || {});
  ids.sort((a, b) => (Date.parse(org.messages[b]?.createdAt || "") || 0) - (Date.parse(org.messages[a]?.createdAt || "") || 0));

  for (const id of ids) {
    const rec = org.messages[id];
    if (!rec) continue;

    const kv = String(rec.kekVersion || org.keyring?.active || "1");
    const kk = getKekByVersion(org, kv);
    if (!kk) continue;

    let msg;
    try { msg = openWithKek(kk.kekBytes, rec.sealed); } catch { continue; }
    if (!msg?.wrappedKeys?.[user.userId]) continue;

    const attCount = Array.isArray(msg.attachments) ? msg.attachments.length : 0;
    const attBytes = Array.isArray(msg.attachments) ? msg.attachments.reduce((s, a) => s + Number(a?.size || 0), 0) : 0;

    items.push({ id, createdAt: rec.createdAt, from: rec.createdByUsername || null, fromUserId: rec.createdByUserId || null, attachmentCount: attCount, attachmentsTotalBytes: attBytes });
  }

  res.json({ items });
});

app.get("/api/messages/:id", requireAuth, async (req, res) => {
  const orgId = req.qm.tokenPayload.orgId;
  const { org, user } = req.qm;

  const id = String(req.params.id || "").trim();
  const rec = org.messages?.[id];
  if (!rec) return res.status(404).json({ error: "Not found" });

  const kv = String(rec.kekVersion || org.keyring?.active || "1");
  const kk = getKekByVersion(org, kv);
  if (!kk) return res.status(500).json({ error: "Missing KEK for stored message" });

  let msg;
  try { msg = openWithKek(kk.kekBytes, rec.sealed); }
  catch { return res.status(500).json({ error: "Failed to open message record (bad KEK)" }); }

  const wrappedDek = msg.wrappedKeys?.[user.userId];
  if (!wrappedDek) {
    await audit(req, orgId, user.userId, "decrypt_denied", { msgId: id, reason: "missing_wrapped_key" });
    return res.status(403).json({ error: "No wrapped key for this user" });
  }

  await audit(req, orgId, user.userId, "decrypt_payload", { msgId: id, kekVersion: kv });

  res.json({
    id,
    createdAt: rec.createdAt,
    iv: msg.iv,
    ciphertext: msg.ciphertext,
    aad: msg.aad,
    wrappedDek,
    kekVersion: kv,
    attachments: Array.isArray(msg.attachments) ? msg.attachments : [],
  });
});

/* =========================================================
   Portal static + routes
========================================================= */
const portalDir = path.join(__dirname, "..", "portal");

app.use("/portal", express.static(portalDir, { extensions: ["html"], etag: false, maxAge: 0 }));

app.get("/m/:id", (_req, res) => res.sendFile(path.join(portalDir, "decrypt.html")));
app.get("/portal/m/:id", (req, res) => res.redirect(`/m/${req.params.id}`));
app.get("/", (_req, res) => res.redirect("/portal/index.html"));

/* =========================================================
   Start (Render compatible)
========================================================= */
const PORT = Number(process.env.PORT || "10000");
app.listen(PORT, () => console.log(`QuantumMail server running on port ${PORT}`));
