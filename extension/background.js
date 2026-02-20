// extension/background.js
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

/**
 * NOTE:
 * - This version fixes:
 *   1) Large attachment base64url encode crash (chunked encoding)
 *   2) chrome.tabs.sendMessage lastError handling (clean error)
 *   3) Better diagnostics if content script not available
 *   4) Safer attachment handling (supports bytes[] OR buffer ArrayBuffer)
 */

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

async function sendToTab(tabId, msg) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, msg, (resp) => {
      const err = chrome.runtime.lastError;
      if (err) return reject(new Error(err.message));
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


// ---------- Base64URL helpers (safe for large arrays) ----------
function bytesToB64Url(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  const chunkSize = 0x8000; // 32KB
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

// ---------- AES-GCM helpers for attachments with provided raw DEK ----------
async function encryptBytesWithRawDek(rawDekBytes, plainBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey(
    "raw",
    rawDekBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plainBytes);
  return {
    iv: bytesToB64Url(iv),
    ciphertext: bytesToB64Url(new Uint8Array(ct))
  };
}

async function decryptBytesWithRawDek(rawDekBytes, ivB64Url, ctB64Url) {
  const iv = b64UrlToU8(ivB64Url);
  const ct = b64UrlToU8(ctB64Url);
  const key = await crypto.subtle.importKey(
    "raw",
    rawDekBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(pt);
}

// ---------- RSA unwrap (for org-mode wrappedDek) ----------
async function rsaUnwrapDek(privateKey, wrappedDekB64Url) {
  const wrappedBytes = b64UrlToBytes(wrappedDekB64Url);
  const raw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, wrappedBytes);
  return new Uint8Array(raw);
}

// ---------- Attachment normalization ----------
function attachmentToU8(a) {
  // Supports either:
  //  - a.bytes: number[] (older popup implementations)
  //  - a.buffer: ArrayBuffer (preferred)
  if (!a) return new Uint8Array();

  if (a.buffer instanceof ArrayBuffer) return new Uint8Array(a.buffer);

  // Some browsers clone ArrayBuffer as {buffer:{}}; guard:
  if (a.buffer?.byteLength != null && typeof a.buffer.slice === "function") {
    return new Uint8Array(a.buffer);
  }

  if (Array.isArray(a.bytes)) return new Uint8Array(a.bytes);

  return new Uint8Array();
}

// ---------- Main flows ----------
async function loginAndStoreSession({ serverBase, orgId, username, password }) {
  const base = normalizeBase(serverBase);
  const out = await apiJson(base, "/auth/login", {
    method: "POST",
    body: { orgId, username, password }
  });

  const token = out.token;
  const user = out.user;

  // ensure local RSA keypair exists and is registered as SPKI on server
  await ensureKeypairAndRegister(base, token);

  await setSession({ serverBase: base, token, user });
  return { base, token, user };
}

async function encryptSelectionOrgWide({ attachments = [] } = {}) {
  const s = await getSession();
  if (!s?.token || !s?.serverBase) throw new Error("Please login first in the popup.");

  const tab = await getActiveTab();
  const tabId = tab.id;
  const aad = aadFromTabUrl(tab.url);

  // get selection from content script (gmail)
  let sel;
  try {
    sel = await sendToTab(tabId, { type: "QM_GET_SELECTION" });
  } catch (e) {
    throw new Error(
      `Could not read selection. Make sure you're on Gmail/Outlook compose and the content script is active. (${e.message})`
    );
  }

  const plaintext = String(sel?.text || "").trim();
  if (!plaintext) throw new Error("Select text in the email body first (compose body).");

  // encrypt body (generates rawDek)
  const { ctB64Url, ivB64Url, rawDek } = await aesEncrypt(plaintext, aad);


  // encrypt attachments with SAME rawDek
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

  // fetch org users to wrap DEK for each
  const usersOut = await apiJson(s.serverBase, "/org/users", { token: s.token });
  const users = Array.isArray(usersOut.users) ? usersOut.users : [];

  const wrappedKeys = {};
  let wrappedCount = 0;
  let skippedNoKey = 0;

  for (const u of users) {
    if (!u?.userId) continue;
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

  // store message on server
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

  const url = msgOut.url;

  // insert link back into compose body
  let rep;
  try {
    rep = await sendToTab(tabId, { type: "QM_REPLACE_SELECTION_WITH_LINK", url });
  } catch (e) {
    throw new Error(`Failed to insert link into email. (${e.message})`);
  }

  if (!rep?.ok) throw new Error(rep?.error || "Failed to insert link into email.");

  return { url, wrappedCount, skippedNoKey, warning: rep?.warning || null };
}

async function loginAndDecrypt({ msgId, serverBase, orgId, username, password }) {
  // login fresh (page supplies creds)
  const { base, token, user } = await loginAndStoreSession({ serverBase, orgId, username, password });

  // fetch encrypted payload (server enforces wrapped key exists for this user)
  const payload = await apiJson(base, `/api/messages/${encodeURIComponent(msgId)}`, { token });

  // unwrap DEK with our local private RSA key
  const kp = await getOrCreateRsaKeypair();
  const rawDek = await rsaUnwrapDek(kp.privateKey, payload.wrappedDek);

  // decrypt body
  // IMPORTANT: this assumes qm.js aesDecrypt supports rawDek override as 3rd param
  // If your aesDecrypt signature differs, tell me and I’ll adjust.
  const plaintext = await aesDecrypt(
  payload.iv,
  payload.ciphertext,
  payload.aad || "web",
  rawDek
);


  // decrypt attachments
  const outAttachments = [];
  const encAtts = Array.isArray(payload.attachments) ? payload.attachments : [];
  for (const a of encAtts) {
    const ptBytes = await decryptBytesWithRawDek(rawDek, a.iv, a.ciphertext);
    outAttachments.push({
      name: a.name || "attachment",
      mimeType: a.mimeType || "application/octet-stream",
      size: Number(a.size || ptBytes.length || 0),
      bytes: Array.from(ptBytes)
    });
  }

  return { plaintext, attachments: outAttachments, user };
}

// ---------- Portal <-> Extension bridge (decrypt page) ----------
// The decrypt page should postMessage:
// { source:"quantummail-portal", type:"QM_LOGIN_AND_DECRYPT_REQUEST", msgId, serverBase, orgId, username, password }
// We respond back:
// { source:"quantummail-extension", type:"QM_DECRYPT_RESULT", ok:true, plaintext, attachments }
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === "QM_LOGIN") {
        const { serverBase, orgId, username, password } = msg;
        await loginAndStoreSession({ serverBase, orgId, username, password });
        sendResponse({ ok: true });
        return;
      }

      if (msg?.type === "QM_ENCRYPT_SELECTION") {
        const out = await encryptSelectionOrgWide({ attachments: msg.attachments || [] });
        sendResponse({ ok: true, ...out });
        return;
      }

      if (msg?.type === "QM_LOGIN_AND_DECRYPT") {
        const { msgId, serverBase, orgId, username, password } = msg;
        const out = await loginAndDecrypt({ msgId, serverBase, orgId, username, password });
        sendResponse({ ok: true, plaintext: out.plaintext, attachments: out.attachments });
        return;
      }

      sendResponse({ ok: false, error: "Unknown message type" });
    } catch (e) {
      console.error(e);
      sendResponse({ ok: false, error: e?.message || String(e) });
    }
  })();

  return true;
});

// Optional: listen for decrypt page postMessage directly if you prefer not using content script.
// You can delete this block if your decrypt page uses chrome.runtime.sendMessage via a content script bridge.
chrome.runtime.onInstalled?.addListener(() => {
  // noop
});
