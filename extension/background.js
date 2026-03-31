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
   API CALL
========================= */
async function apiJson(serverBase, path, { method = "GET", token = "", body = null } = {}) {
  const base = normalizeBase(serverBase);
  const deviceId = await getDeviceId();

  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      "x-qm-device-id": deviceId
    },
    body: body ? JSON.stringify(body) : undefined
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(data.error || "Request failed");
  }

  return data;
}

/* =========================
   LOGIN
========================= */
async function loginAndStoreSession({ serverBase, orgId, username, password }) {
  const base = normalizeBase(serverBase);

  const res = await fetch(`${base}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ orgId, username, password })
  });

  const data = await res.json();

  if (!data.token) throw new Error("Login failed");

  await ensureDeviceRegistered(base, data.token, data.user.userId);

  await setSession({
    serverBase: base,
    token: data.token,
    user: data.user
  });

  return data;
}

/* =========================
   ENCRYPT
========================= */
async function encryptSelection() {
  const s = await getSession();

  const tab = await chrome.tabs.query({ active: true, currentWindow: true });
  const tabId = tab[0].id;

  const sel = await chrome.tabs.sendMessage(tabId, { type: "QM_GET_SELECTION" });
  const text = sel?.text?.trim();

  if (!text) throw new Error("No text selected");

  const { ctB64Url, ivB64Url, rawDek } = await aesEncrypt(text);

  const devices = await apiJson(s.serverBase, "/api/devices/list", {
    token: s.token
  });

  const wrappedKeys = {};

  for (const d of devices.devices) {
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

  const msg = await apiJson(s.serverBase, "/api/messages", {
    method: "POST",
    token: s.token,
    body: {
      iv: ivB64Url,
      ciphertext: ctB64Url,
      wrappedKeys
    }
  });

  await chrome.tabs.sendMessage(tabId, {
    type: "QM_REPLACE_SELECTION_WITH_LINK",
    url: msg.url
  });

  return msg;
}

/* =========================
   MESSAGE ROUTER
========================= */
chrome.runtime.onMessage.addListener((msg, _, sendResponse) => {
  (async () => {
    try {
      if (msg.type === "QM_LOGIN") {
        await loginAndStoreSession(msg);
        sendResponse({ ok: true });
        return;
      }

      if (msg.type === "QM_ENCRYPT_SELECTION") {
        const out = await encryptSelection();
        sendResponse({ ok: true, ...out });
        return;
      }

      if (msg.type === "load_devices") {
        const s = await getSession();

        const data = await apiJson(s.serverBase, "/api/devices/list", {
          token: s.token
        });

        window.postMessage({
          source: "qm-ext",
          type: "devices_loaded",
          payload: data
        });

        sendResponse({ ok: true });
        return;
      }

      if (msg.type === "trust_this_device") {
        const s = await getSession();
        const deviceId = await getDeviceId();

        await apiJson(s.serverBase, "/api/devices/trust", {
          method: "POST",
          token: s.token,
          body: { device_id: deviceId }
        });

        window.postMessage({ source: "qm-ext", type: "device_trusted" });

        sendResponse({ ok: true });
        return;
      }

      if (msg.type === "revoke_device") {
        const s = await getSession();

        await apiJson(s.serverBase, "/api/devices/revoke", {
          method: "POST",
          token: s.token,
          body: { device_id: msg.payload.device_id }
        });

        window.postMessage({ source: "qm-ext", type: "device_revoked" });

        sendResponse({ ok: true });
        return;
      }


      /* =========================
         START RECOVERY
      ========================= */
      if (msg.type === "start_recovery") {
        const s = await getSession();
      
        const data = await apiJson(s.serverBase, "/api/recovery/start", {
          method: "POST",
          token: s.token
        });
      
        window.postMessage({
          source: "qm-ext",
          type: "recovery_started",
          payload: data
        });
      
        sendResponse({ ok: true });
        return;
      }
      
      /* =========================
         LOAD PENDING
      ========================= */
      if (msg.type === "load_pending") {
        const s = await getSession();
      
        const data = await apiJson(s.serverBase, "/api/recovery/pending", {
          token: s.token
        });
      
        window.postMessage({
          source: "qm-ext",
          type: "pending_loaded",
          payload: data
        });
      
        sendResponse({ ok: true });
        return;
      }
      
      /* =========================
         APPROVE RECOVERY
      ========================= */
      if (msg.type === "approve_recovery") {
        const s = await getSession();
      
        const kp = await getOrCreateRsaKeypair(s.user.userId);
        const privateJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
      
        const encrypted = btoa(JSON.stringify(privateJwk));
      
        await apiJson(s.serverBase, "/api/recovery/approve", {
          method: "POST",
          token: s.token,
          body: {
            request_id: msg.payload.request_id,
            encrypted_private_key: encrypted
          }
        });
      
        window.postMessage({
          source: "qm-ext",
          type: "recovery_approved"
        });
      
        sendResponse({ ok: true });
        return;
      }
      
      /* =========================
         FINISH RECOVERY
      ========================= */
      if (msg.type === "finish_recovery") {
        const s = await getSession();
      
        const data = await apiJson(
          s.serverBase,
          `/api/recovery/finish/${msg.payload.request_id}`,
          { token: s.token }
        );
      
        const privateJwk = JSON.parse(atob(data.encrypted_key));
      
        await chrome.storage.local.set({
          [`qm_rsa_${s.user.userId}`]: {
            privateJwk,
            publicJwk: privateJwk 
          }
        });
      
        window.postMessage({
          source: "qm-ext",
          type: "vault_recovered"
        });
      
        sendResponse({ ok: true });
        return;
      }
      
      sendResponse({ ok: false });
    } catch (e) {
      sendResponse({ ok: false, error: e.message });
    }
  })();

  return true;
});
