// extension/background.js
// QuantumMail (latest ideology):
// - Single login in popup -> background stores session (serverBase + token + user)
// - On login: ensure local RSA keypair exists and register SPKI via /org/register-key
// - Encrypt selected text (Gmail/Outlook/web) -> AES-GCM -> wrap DEK per org user public keys -> POST /api/messages
// - Replace selection with decrypt link in compose body
// - Decrypt flow: login (or reuse session) -> GET /api/messages/:id -> unwrap DEK -> decrypt body + attachments
//
// This version is hardened:
// ✅ Handles server returning HTML on 500 (parses text fallback and shows useful error)
// ✅ Better lastError handling for chrome.tabs.sendMessage
// ✅ Stronger attachment base64url encoding (chunked)
// ✅ Clear “content script not available” diagnostics
// ✅ Safer attachment normalization (bytes[] or ArrayBuffer)

import {
  normalizeBase,
  getSession,
  setSession,
  ensureKeypairAndRegister,
  aesEncrypt,
  aesDecrypt,
  importPublicSpkiB64,
  rsaWrapDek,
  b64UrlToBytes,
  getOrCreateRsaKeypair
} from "./qm.js";

/* =========================
   Robust fetch helpers
========================= */
async function readBodySmart(res) {
  const ct = String(res.headers.get("content-type") || "").toLowerCase();

  // Prefer JSON if available
  if (ct.includes("application/json")) {
    try {
      return { kind: "json", data: await res.json() };
    } catch {
      // fall through to text
    }
  }

  // Fallback: text (HTML or plain)
  try {
    const t = await res.text();
    return { kind: "text", data: t };
  } catch {
    return { kind: "none", data: null };
  }
}

function shortenText(s, n = 240) {
  const str = String(s || "");
  if (str.length <= n) return str;
  return str.slice(0, n) + "…";
}

async function apiJson(serverBase, path, { method = "GET", token = "", body = null } = {}) {
  const headers = { Accept: "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers["Content-Type"] = "application/json";

  const url = `${serverBase}${path}`;

  let res;
  try {
    res = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    });
  } catch (e) {
    throw new Error(`Network error calling ${path}: ${e?.message || e}`);
  }

  const parsed = await readBodySmart(res);

  if (!res.ok) {
    // Try to extract error meaningfully
    const jsonErr =
      parsed.kind === "json"
        ? (parsed.data?.error || parsed.data?.message || null)
        : null;

    const textErr =
      parsed.kind === "text"
        ? shortenText(parsed.data, 280)
        : null;

    const msg = jsonErr || textErr || `Request failed (${res.status})`;
    throw new Error(msg);
  }

  // Always return JSON object if possible
  if (parsed.kind === "json") return parsed.data;

  // If server returned non-json but ok, return text wrapper
  return { ok: true, raw: parsed.data };
}

/* =========================
   Chrome tab messaging
========================= */
async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error("No active tab");
  return tab;
}

async function sendToTab(tabId, msg) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, msg, (resp) => {
      const err = chrome.runtime.lastError;
      if (err) {
        // Typical: "Could not establish connection. Receiving end does not exist."
        return reject(new Error(err.message));
      }
      resolve(resp);
    });
  });
}

function aadFromTabUrl(tabUrl) {
  const u = String(tabUrl || "").toLowerCase();
  if (u.includes("mail.google.com")) return "gmail";
  if (u.includes("outlook.office.com")) return "outlook";
  if (u.includes("outlook.live.com")) return "outlook";
  return "web";
}

/* =========================
   Base64URL for large data
========================= */
function bytesToB64Url(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  const chunkSize = 0x8000; // 32KB chunks to avoid call stack overflow
  let binary = "";
  for (let i = 0; i < u8.length; i += chunkSize) {
    const chunk = u8.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, chunk);
  }
  const b64 = btoa(binary);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64UrlToU8(b64url) {
  return b64UrlToBytes(b64url); // from qm.js
}

/* =========================
   Attachment crypto (same DEK)
========================= */
async function encryptBytesWithRawDek(rawDekBytes, plainBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", rawDekBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plainBytes);
  return { iv: bytesToB64Url(iv), ciphertext: bytesToB64Url(new Uint8Array(ct)) };
}

async function decryptBytesWithRawDek(rawDekBytes, ivB64Url, ctB64Url) {
  const iv = b64UrlToU8(ivB64Url);
  const ct = b64UrlToU8(ctB64Url);
  const key = await crypto.subtle.importKey("raw", rawDekBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(pt);
}

// RSA unwrap DEK for org-mode
async function rsaUnwrapDek(privateKey, wrappedDekB64Url) {
  const wrappedBytes = b64UrlToBytes(wrappedDekB64Url);
  const raw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, wrappedBytes);
  return new Uint8Array(raw);
}

// Normalize attachments coming from popup (bytes[] OR ArrayBuffer)
function attachmentToU8(a) {
  if (!a) return new Uint8Array();

  if (a.buffer instanceof ArrayBuffer) return new Uint8Array(a.buffer);

  if (a.buffer?.byteLength != null && typeof a.buffer.slice === "function") {
    return new Uint8Array(a.buffer);
  }

  if (Array.isArray(a.bytes)) return new Uint8Array(a.bytes);

  return new Uint8Array();
}

/* =========================
   Session + login
========================= */
async function loginAndStoreSession({ serverBase, orgId, username, password }) {
  const base = normalizeBase(serverBase);

  // Login
  const out = await apiJson(base, "/auth/login", {
    method: "POST",
    body: { orgId, username, password }
  });

  const token = out?.token || "";
  const user = out?.user || null;
  if (!token || !user) throw new Error("Login failed: missing token/user.");

  // Ensure RSA keypair exists + register public key with server
  // ensureKeypairAndRegister(base, token) should POST /org/register-key internally
  await ensureKeypairAndRegister(base, token);

  // Save session for popup + content scripts
  await setSession({ serverBase: base, token, user });

  return { base, token, user };
}

/* =========================
   Encrypt selection org-wide
========================= */
async function encryptSelectionOrgWide({ attachments = [] } = {}) {
  const s = await getSession();
  if (!s?.token || !s?.serverBase) {
    throw new Error("Please login first in the popup.");
  }

  const tab = await getActiveTab();
  const tabId = tab.id;
  const aad = aadFromTabUrl(tab.url);

  // Selection from content script
  let sel;
  try {
    sel = await sendToTab(tabId, { type: "QM_GET_SELECTION" });
  } catch (e) {
    throw new Error(
      `Could not read selection. Open Gmail/Outlook compose, ensure extension is enabled, then refresh the tab. (${e.message})`
    );
  }

  const plaintext = String(sel?.text || "").trim();
  if (!plaintext) throw new Error("Select text in the email body first (compose body).");

  // Encrypt body (returns rawDek)
  const { ctB64Url, ivB64Url, rawDek } = await aesEncrypt(plaintext, aad);

  // Encrypt attachments with SAME rawDek
  const encAttachments = [];
  const list = Array.isArray(attachments) ? attachments : [];
  for (const a of list) {
    const bytes = attachmentToU8(a);
    if (!bytes || bytes.length === 0) continue;

    const ea = await encryptBytesWithRawDek(rawDek, bytes);
    encAttachments.push({
      name: a.name || "attachment",
      mimeType: a.mimeType || "application/octet-stream",
      size: Number(a.size || bytes.length || 0),
      iv: ea.iv,
      ciphertext: ea.ciphertext
    });
  }

  // Get org users so we can wrap DEK for each user with a public key
  const usersOut = await apiJson(s.serverBase, "/org/users", { token: s.token });
  const users = Array.isArray(usersOut?.users) ? usersOut.users : [];

  const wrappedKeys = {};
  let wrappedCount = 0;
  let skippedNoKey = 0;

  for (const u of users) {
    if (!u?.userId) continue;

    // Important: your server returns publicKeySpkiB64 for /org/users currently.
    // If you ever stop returning it for privacy, add a new admin endpoint.
    if (!u.publicKeySpkiB64) {
      skippedNoKey++;
      continue;
    }

    const pub = await importPublicSpkiB64(u.publicKeySpkiB64);
    const wrappedDek = await rsaWrapDek(pub, rawDek);
    wrappedKeys[u.userId] = wrappedDek;
    wrappedCount++;
  }

  if (wrappedCount === 0) {
    throw new Error("No org users have public keys registered yet. Have at least one user login once.");
  }

  // Store message on server
  const msgOut = await apiJson(s.serverBase, "/api/messages", {
    method: "POST",
    token: s.token,
    body: {
      iv: ivB64Url,
      ciphertext: ctB64Url,
      aad,
      wrappedKeys,
      attachments: encAttachments
    }
  });

  const url = msgOut?.url;
  if (!url) throw new Error("Server did not return message URL.");

  // Insert link into compose body
  let rep;
  try {
    rep = await sendToTab(tabId, { type: "QM_REPLACE_SELECTION_WITH_LINK", url });
  } catch (e) {
    throw new Error(`Failed to insert link into email. (${e.message})`);
  }

  if (!rep?.ok) throw new Error(rep?.error || "Failed to insert link into email.");

  return { url, wrappedCount, skippedNoKey, warning: rep?.warning || null };
}

/* =========================
   Login + decrypt message
========================= */
async function loginAndDecrypt({ msgId, serverBase, orgId, username, password }) {
  // Fresh login (decrypt page supplies creds)
  const { base, token } = await loginAndStoreSession({ serverBase, orgId, username, password });

  // Fetch encrypted payload (server enforces wrapped key exists for this user)
  const payload = await apiJson(base, `/api/messages/${encodeURIComponent(msgId)}`, { token });

  if (!payload?.wrappedDek) throw new Error("Missing wrappedDek in payload.");

  // Unwrap DEK with our local private RSA key
  const kp = await getOrCreateRsaKeypair();
  const rawDek = await rsaUnwrapDek(kp.privateKey, payload.wrappedDek);

  // Decrypt body
  // IMPORTANT: aesDecrypt in qm.js must accept rawDek override (4th arg)
  const plaintext = await aesDecrypt(
    payload.iv,
    payload.ciphertext,
    payload.aad || "web",
    rawDek
  );

  // Decrypt attachments (if any)
  const outAttachments = [];
  const encAtts = Array.isArray(payload.attachments) ? payload.attachments : [];
  for (const a of encAtts) {
    if (!a?.iv || !a?.ciphertext) continue;
    const ptBytes = await decryptBytesWithRawDek(rawDek, a.iv, a.ciphertext);
    outAttachments.push({
      name: a.name || "attachment",
      mimeType: a.mimeType || "application/octet-stream",
      size: Number(a.size || ptBytes.length || 0),
      bytes: Array.from(ptBytes)
    });
  }

  return { plaintext, attachments: outAttachments };
}

/* =========================
   Message router (popup / portal bridge)
========================= */
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      // Login from popup
      if (msg?.type === "QM_LOGIN") {
        const { serverBase, orgId, username, password } = msg;
        await loginAndStoreSession({ serverBase, orgId, username, password });
        sendResponse({ ok: true });
        return;
      }

      // Encrypt selection from popup
      if (msg?.type === "QM_ENCRYPT_SELECTION") {
        const out = await encryptSelectionOrgWide({ attachments: msg.attachments || [] });
        sendResponse({ ok: true, ...out });
        return;
      }

      // Login + decrypt from portal decrypt page bridge
      if (msg?.type === "QM_LOGIN_AND_DECRYPT") {
        const { msgId, serverBase, orgId, username, password } = msg;
        const out = await loginAndDecrypt({ msgId, serverBase, orgId, username, password });
        sendResponse({ ok: true, plaintext: out.plaintext, attachments: out.attachments });
        return;
      }

      sendResponse({ ok: false, error: "Unknown message type" });
    } catch (e) {
      console.error("QuantumMail background error:", e);
      sendResponse({ ok: false, error: e?.message || String(e) });
    }
  })();

  return true; // async
});

// Keep installed hook (noop)
chrome.runtime.onInstalled?.addListener(() => {});
