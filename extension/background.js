// extension/background.js (FINAL)

import {
  normalizeBase,
  getSession,
  setSession,
  aesEncrypt,
  aesDecrypt,
  rsaWrapDek,
  getOrCreateRsaKeypair,
  ensureDeviceRegistered,
  getDeviceId
} from "./qm.js";

/* =========================
   Helpers
========================= */

function shortenText(s, n = 280) {
  const str = String(s || "");
  return str.length <= n ? str : str.slice(0, n) + "…";
}

async function exportPublicJwkForCurrentUser(userId) {
  const { publicKey } = await getOrCreateRsaKeypair(userId);
  return await crypto.subtle.exportKey("jwk", publicKey);
}

async function readResponseSmart(res) {
  const ct = String(res.headers.get("content-type") || "").toLowerCase();
  const raw = await res.text().catch(() => "");

  if (ct.includes("application/json")) {
    try {
      return { kind: "json", data: JSON.parse(raw || "{}"), raw };
    } catch {
      return { kind: "text", data: raw, raw };
    }
  }

  return { kind: "text", data: raw, raw };
}


async function encryptSelectionOrgWide({ attachments = [], recipientUserIds = [] }) {
  const s = await getSession();

  const tab = await chrome.tabs.query({ active: true, currentWindow: true });
  const tabId = tab[0].id;

  const sel = await chrome.tabs.sendMessage(tabId, { type: "QM_GET_SELECTION" });
  const plaintext = String(sel?.text || "").trim();

  if (!plaintext) throw new Error("No selected text");

  const { ctB64Url, ivB64Url, rawDek } = await aesEncrypt(plaintext, "gmail");

  // 🔐 DEVICE-BASED WRAPPING
  const devicesOut = await apiJson(s.serverBase, "/api/devices/list", {
    token: s.token
  });

  const devices = devicesOut.devices || [];

  const wrappedKeys = {};

  /*for (const d of devices) {
    if (!d.deviceId || !d.publicKeySpkiB64) continue;
    if (d.status !== "active") continue;

    const pub = await importPublicSpkiB64(d.publicKeySpkiB64);
    wrappedKeys[d.deviceId] = await rsaWrapDek(pub, rawDek);*/
  for (const d of devices) {
    if (d.status !== "active") continue; 
  
    const pub = await crypto.subtle.importKey(
      "jwk",
      d.pub_jwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["encrypt"]
    );
  
    wrappedKeys[d.device_id] = await rsaWrapDek(pub, rawDek);
  }

    const msgOut = await apiJson(s.serverBase, "/api/messages", {
      method: "POST",
      token: s.token,
      body: {
        iv: ivB64Url,
        ciphertext: ctB64Url,
        aad: "gmail",
        wrappedKeys,
        attachments
      }
    });
  
    await chrome.tabs.sendMessage(tabId, {
      type: "QM_REPLACE_SELECTION_WITH_LINK",
      url: msgOut.url
    });

  return {
    url: msgOut.url,
    wrappedCount: Object.keys(wrappedKeys).length
  };
}
/* =========================
   API CALL (with device binding)
========================= */

async function apiJson(serverBase, path, { method = "GET", token = "", body = null } = {}) {
  const base = normalizeBase(serverBase);
  const url = `${base}${path}`;

  const headers = { Accept: "application/json" };

  // 🔐 device binding
  const deviceId = await getDeviceId?.().catch(() => null);
  if (deviceId) headers["x-qm-device-id"] = deviceId;

  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers["Content-Type"] = "application/json";

  let res;
  try {
    res = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    });
  } catch (e) {
    throw new Error(`[NET] ${method} ${path} -> ${e?.message || e}`);
  }

  const parsed = await readResponseSmart(res);

  if (!res.ok) {
    const msg =
      (parsed.kind === "json" && (parsed.data?.error || parsed.data?.message)) ||
      shortenText(parsed.raw || parsed.data || "", 320) ||
      `Request failed (${res.status})`;

    throw new Error(`[HTTP ${res.status}] ${method} ${path} -> ${msg}`);
  }

  return parsed.kind === "json" ? parsed.data : { ok: true, raw: parsed.data };
}

/* =========================
   AUTH
========================= */

async function loginAndStoreSession({ serverBase, orgId, username, password }) {
  const base = normalizeBase(serverBase);

  const out = await apiJson(base, "/auth/login", {
    method: "POST",
    body: { orgId, username, password }
  });

  const token = out?.token || "";
  const user = out?.user || null;

  if (!token || !user?.userId) {
    throw new Error("Login failed: missing token/user.");
  }

  await ensureDeviceRegistered(base, token, user.userId);
  await setSession({ serverBase: base, token, user });

  return { base, token, user };
}

/* =========================
   DECRYPT
========================= */

async function loginAndDecrypt({ msgId, serverBase, orgId, username, password }) {
  const { base, token, user } = await loginAndStoreSession({
    serverBase,
    orgId,
    username,
    password
  });

  console.log("DECRYPT: fetching message", msgId);

  const payload = await apiJson(
    base,
    `/api/messages/${encodeURIComponent(msgId)}`,
    { token }
  );

  console.log("DECRYPT: payload", payload);

  // 🔥 FIX: support both formats
  const wrappedDek = payload.wrappedDek || payload.wrappedKey;

  if (!wrappedDek) {
    throw new Error("Missing wrapped key in payload.");
  }

  const kp = await getOrCreateRsaKeypair(user.userId);

  let rawDek;
  try {
    rawDek = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      kp.privateKey,
      b64UrlToBytes(wrappedDek)
    );
  } catch {
    throw new Error(
      "Decrypt failed: device key mismatch.\n" +
      "Reinstall/re-key likely happened.\n" +
      "Ask sender to re-encrypt."
    );
  }

  const plaintext = await aesDecrypt(
    payload.iv,
    payload.ciphertext,
    payload.aad || "web",
    new Uint8Array(rawDek)
  );

  return {
    plaintext,
    attachments: payload.attachments || []
  };
}

/* =========================
   MESSAGE ROUTER
========================= */

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      console.log("BACKGROUND received:", msg);

      /* LOGIN */
      if (msg?.type === "QM_LOGIN") {
        await loginAndStoreSession(msg);
        sendResponse({ ok: true });
        return;
      }

      if (msg?.type === "QM_RECIPIENTS") {
        const s = await getSession();
      
        if (!s?.token || !s?.serverBase) {
          sendResponse({ ok: false, error: "Not logged in" });
          return;
        }
      
        const usersOut = await apiJson(s.serverBase, "/org/users", {
          token: s.token
        });
      
        const users = Array.isArray(usersOut?.users)
          ? usersOut.users
          : [];
      
        sendResponse({
          ok: true,
          users: users.map(u => ({
            userId: u.userId,
            username: u.username,
            hasKey: !!u.publicKeySpkiB64
          }))
        });
      
        return;
      }

      /* TRUST DEVICE */
      if (msg?.type === "trust_this_device") {
        const s = await getSession();
        const deviceId = await getDeviceId();
      
        await apiJson(s.serverBase, "/api/devices/trust", {
          method: "POST",
          token: s.token,
          body: { device_id: deviceId }
        });
      
        window.postMessage({
          source: "qm-ext",
          type: "device_trusted"
        });
      
        sendResponse({ ok: true });
        return;
      }
      
      if (msg?.type === "QM_ENCRYPT_SELECTION") {
        const s = await getSession();
      
        if (!s?.token || !s?.serverBase) {
          sendResponse({ ok: false, error: "Not logged in" });
          return;
        }
      
        try {
          const out = await encryptSelectionOrgWide({
            attachments: msg.attachments || [],
            recipientUserIds: msg.recipientUserIds || []
          });
      
          sendResponse({ ok: true, ...out });
        } catch (e) {
          sendResponse({ ok: false, error: e.message || String(e) });
        }
      
        return;
      }
      
      /* DECRYPT */
      if (msg?.type === "QM_LOGIN_AND_DECRYPT") {
        const out = await loginAndDecrypt(msg);

        sendResponse({
          ok: true,
          plaintext: out.plaintext,
          attachments: out.attachments
        });
        return;
      }

      /* LOAD DEVICES */
      if (msg?.type === "load_devices") {
        const s = await getSession();

        const data = await apiJson(s.serverBase, "/api/devices/list", {
          token: s.token
        });

        window.postMessage({
          source: "qm-ext",
          type: "devices_loaded",
          payload: { devices: data.devices || [] }
        });

        sendResponse({ ok: true });
        return;
      }

      /* REVOKE DEVICE */
      if (msg?.type === "revoke_device") {
        const s = await getSession();

        await apiJson(s.serverBase, "/org/revoke-device", {
          method: "POST",
          token: s.token,
          body: { deviceId: msg.payload.device_id }
        });

        window.postMessage({
          source: "qm-ext",
          type: "device_revoked"
        });

        sendResponse({ ok: true });
        return;
      }

      sendResponse({ ok: false, error: "Unknown message type" });
    } catch (e) {
      console.error("QuantumMail background error:", e);
      sendResponse({ ok: false, error: e.message || String(e) });
    }
  })();

  return true;
});
