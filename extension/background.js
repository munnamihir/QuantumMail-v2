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

async function apiJson(serverBase, path, { method = "GET", token = "", body = null } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers["Content-Type"] = "application/json";

  const res = await fetch(`${serverBase}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

async function getActiveTabId() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error("No active tab");
  return tab.id;
}

async function sendToTab(tabId, msg) {
  return new Promise((resolve) => {
    chrome.tabs.sendMessage(tabId, msg, (resp) => resolve(resp));
  });
}

// ---------- AES-GCM helpers for attachments with provided raw DEK ----------
function bytesToB64Url(bytes) {
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64UrlToU8(b64url) {
  return b64UrlToBytes(b64url); // from qm.js
}

async function encryptBytesWithRawDek(rawDekBytes, plainBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", rawDekBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plainBytes);
  return {
    iv: bytesToB64Url(iv),
    ciphertext: bytesToB64Url(new Uint8Array(ct))
  };
}

async function decryptBytesWithRawDek(rawDekBytes, ivB64Url, ctB64Url) {
  const iv = b64UrlToU8(ivB64Url);
  const ct = b64UrlToU8(ctB64Url);
  const key = await crypto.subtle.importKey("raw", rawDekBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(pt);
}

// ---------- RSA unwrap (for org-mode wrappedDek) ----------
async function rsaUnwrapDek(privateKey, wrappedDekB64Url) {
  const wrappedBytes = b64UrlToBytes(wrappedDekB64Url);
  const raw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, wrappedBytes);
  return new Uint8Array(raw);
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

  const tabId = await getActiveTabId();

  // get selection from content script (gmail)
  const sel = await sendToTab(tabId, { type: "QM_GET_SELECTION" });
  const plaintext = String(sel?.text || "").trim();
  if (!plaintext) throw new Error("Select text in the email body first (compose body).");

  // encrypt body (generates rawDek)
  const { ciphertextB64, ivB64, rawDek } = await aesEncrypt(plaintext);

  // encrypt attachments with SAME rawDek
  const encAttachments = [];
  for (const a of Array.isArray(attachments) ? attachments : []) {
    const bytes = new Uint8Array(a.bytes || []);
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
    if (!u.publicKeySpkiB64) { skippedNoKey++; continue; }

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
      iv: ivB64,
      ciphertext: ciphertextB64,
      aad: "gmail",
      wrappedKeys,
      attachments: encAttachments
    }
  });

  const url = msgOut.url;

  // insert link back into compose body
  const rep = await sendToTab(tabId, { type: "QM_REPLACE_SELECTION_WITH_LINK", url });
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
  const plaintext = await aesDecrypt(payload.ciphertext, payload.iv, rawDek);

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

  return {
    plaintext,
    attachments: outAttachments,
    user
  };
}

// ---------- Message router ----------
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
