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
import { bytesToB64Url } from "./qm.js";

async function encryptAttachmentBytes(rawDekBytes, file) {
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const dek = await crypto.subtle.importKey(
    "raw",
    rawDekBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    dek,
    new Uint8Array(file.bytes)
  );

  return {
    name: file.name,
    mimeType: file.mimeType,
    iv: bytesToB64Url(iv),
    ciphertext: bytesToB64Url(new Uint8Array(ct))
  };
}


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

function findUserByUsername(users, username) {
  const target = String(username || "").trim().toLowerCase();
  return (users || []).find((u) => String(u.username || "").trim().toLowerCase() === target);
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error("No active tab");
  return tab;
}

// async function tabMessage(tabId, message) {
//   return new Promise((resolve) => {
//     chrome.tabs.sendMessage(tabId, message, (resp) => resolve(resp));
//   });
// }
async function tabMessage(tabId, message) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, message, (resp) => {
      const err = chrome.runtime.lastError;
      if (err) {
        reject(new Error(`Content script not available. Refresh the Gmail tab and try again. (${err.message})`));
        return;
      }
      resolve(resp);
    });
  });
}


/**
 * Org-wide envelope encryption:
 * - Per-message AES-GCM key (DEK)
 * - DEK wrapped (RSA-OAEP) for every active user with a registered public key
 * - Anyone in the org (with a public key) can decrypt after login.
 */
async function encryptSelectionOrgWide(session, attachmentsInput = []){
  if (!session?.token) throw new Error("Not logged in");

  const tab = await getActiveTab();

  // 1) Get selected plaintext from Gmail/editor
  const sel = await tabMessage(tab.id, { type: "QM_GET_SELECTION" });
  const selectedText = String(sel?.text || "").trim();
  if (!selectedText) throw new Error("Select text in the email body first.");

  // 2) Fetch org users
  const orgUsers = await apiJson(session.serverBase, "/org/users", { token: session.token });
  const users = orgUsers.users || [];

  // 3) Encrypt plaintext with per-message AES-GCM
  const enc = await aesEncrypt(selectedText, "gmail");
  // Encrypt attachments using SAME raw DEK
  const encryptedAttachments = [];

  for (const file of attachmentsInput || []) {
    const encFile = await encryptAttachmentBytes(enc.rawDek, file);
    encryptedAttachments.push(encFile);
  }

  // 4) Wrap DEK for all active users with pubkeys
  const wrappedKeys = {};

  const me =
    users.find((u) => u.userId === session.user?.userId) ||
    findUserByUsername(users, session.user?.username);

  if (!me) throw new Error("Sender not found in org/users");
  if (!me.publicKeySpkiB64) {
    throw new Error(`User "${session.user?.username}" has no public key registered (login once).`);
  }

  let wrappedCount = 0;
  let skippedNoKey = 0;

  for (const u of users) {
    // You can enforce additional policy here (e.g., only 'Active' users)
    if (u.status && String(u.status).toLowerCase() === "disabled") continue;

    if (!u.publicKeySpkiB64) {
      skippedNoKey++;
      continue; // user must login once to register pubkey
    }

    const pub = await importPublicSpkiB64(u.publicKeySpkiB64);
    wrappedKeys[u.userId] = await rsaWrapDek(pub, enc.rawDek);
    wrappedCount++;
  }

  // Safety: ensure sender included
  if (!wrappedKeys[me.userId]) {
    const pub = await importPublicSpkiB64(me.publicKeySpkiB64);
    wrappedKeys[me.userId] = await rsaWrapDek(pub, enc.rawDek);
    wrappedCount++;
  }

  if (wrappedCount === 0) {
    throw new Error("No users with public keys found. Ask users to login once to register keys.");
  }

  // 5) Store message on server
  const saved = await apiJson(session.serverBase, "/api/messages", {
    method: "POST",
    token: session.token,
    body: {
      iv: enc.ivB64Url,
      ciphertext: enc.ctB64Url,
      aad: enc.aad,
      wrappedKeys,
      attachments: encryptedAttachments
    }

  });

  const url = saved.url;
  if (!url) throw new Error("Server did not return url");

  // 6) Insert link into Gmail/editor
  const ins = await tabMessage(tab.id, { type: "QM_REPLACE_SELECTION_WITH_LINK", url });
  if (!ins?.ok) throw new Error(ins?.error || "Could not insert link");

  return { url, skippedNoKey, wrappedCount };
}

async function login(serverBase, orgId, username, password) {
  const data = await apiJson(serverBase, "/auth/login", {
    method: "POST",
    body: { orgId, username, password }
  });

  // Save session
  await setSession({ serverBase, token: data.token, user: data.user });

  // Ensure this browser has RSA keypair + register pubkey to server
  await ensureKeypairAndRegister(serverBase, data.token);

  return data;
}

async function loginAndDecrypt({ serverBase, orgId, username, password, msgId }) {
  // 1) Login (audited on server when message fetched)
  const auth = await apiJson(serverBase, "/auth/login", {
    method: "POST",
    body: { orgId, username, password }
  });

  // 2) Ensure pubkey exists (first-time user)
  await ensureKeypairAndRegister(serverBase, auth.token);

  // 3) Fetch message payload (server returns wrappedDek for THIS user only)
  const payload = await apiJson(serverBase, `/api/messages/${encodeURIComponent(msgId)}`, {
    token: auth.token
  });

  //const { iv, ciphertext, aad, wrappedDek } = payload || {};
  const { iv, ciphertext, aad, wrappedDek, attachments = [] } = payload || {};
  if (!iv || !ciphertext || !wrappedDek) throw new Error("Message not loaded (missing fields)");

  // 4) Unwrap DEK with RSA private key (stored in this browser extension)
  const { privateKey } = await getOrCreateRsaKeypair();
  const wrappedBytes = b64UrlToBytes(wrappedDek);

  let rawDekBytes;
  try {
    const raw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, wrappedBytes);
    rawDekBytes = new Uint8Array(raw);
  } catch {
    throw new Error("Failed to unwrap key. Wrong user or key mismatch on this browser.");
  }

  // 5) AES-GCM decrypt
  const plaintext = await aesDecrypt(iv, ciphertext, aad || "gmail", rawDekBytes);
  const decryptedAttachments = [];

for (const a of attachments) {
  const fileIv = b64UrlToBytes(a.iv);
  const fileCt = b64UrlToBytes(a.ciphertext);

  const dek = await crypto.subtle.importKey(
    "raw",
    rawDekBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const filePlain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fileIv },
    dek,
    fileCt
  );

  decryptedAttachments.push({
    name: a.name,
    mimeType: a.mimeType || "application/octet-stream",
    bytes: Array.from(new Uint8Array(filePlain))
  });
}

  return { plaintext, attachments: decryptedAttachments };

}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      // -----------------------
      // LOGIN (popup)
      // -----------------------
      if (msg?.type === "QM_LOGIN") {
        const serverBase = normalizeBase(msg.serverBase);
        const orgId = String(msg.orgId || "").trim();
        const username = String(msg.username || "").trim();
        const password = String(msg.password || "");

        if (!serverBase || !orgId || !username || !password) {
          throw new Error("serverBase, orgId, username, password required");
        }

        await login(serverBase, orgId, username, password);
        sendResponse({ ok: true });
        return;
      }

      // -----------------------
      // ENCRYPT SELECTION (recipientless / org-wide)
      // -----------------------
      if (msg?.type === "QM_ENCRYPT_SELECTION") {
        const s = await getSession();
        const attachments = msg.attachments || [];
        if (!s?.token) throw new Error("Not logged in");

        //const out = await encryptSelectionOrgWide(s);
        const out = await encryptSelectionOrgWide(s, attachments);
        sendResponse({ ok: true, url: out.url, wrappedCount: out.wrappedCount, skippedNoKey: out.skippedNoKey });
        return;
      }

      // -----------------------
      // LOGIN + DECRYPT (decrypt page provides creds)
      // -----------------------
      if (msg?.type === "QM_LOGIN_AND_DECRYPT") {
        const serverBase = normalizeBase(msg.serverBase);
        const orgId = String(msg.orgId || "").trim();
        const username = String(msg.username || "").trim();
        const password = String(msg.password || "");
        const msgId = String(msg.msgId || "").trim();

        if (!serverBase || !orgId || !username || !password) throw new Error("Missing credentials");
        if (!msgId) throw new Error("Missing message id");

        const plaintext = await loginAndDecrypt({ serverBase, orgId, username, password, msgId });
        //sendResponse({ ok: true, plaintext });
        sendResponse({ ok: true, plaintext, attachments });

        return;
      }

      sendResponse({ ok: false, error: "Unknown message type" });
    } catch (e) {
      sendResponse({ ok: false, error: e?.message || String(e) });
    }
  })();

  return true;
});
