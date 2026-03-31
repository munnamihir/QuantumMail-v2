// extension/background.js (FINAL CLEAN)

import {
  normalizeBase,
  getSession,
  setSession,
  aesEncrypt,
  rsaWrapDek,
  getOrCreateRsaKeypair,
  ensureDeviceRegistered,
  getDeviceId
} from "./qm.js";

/* =========================
   API HELPER
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

  if (!res.ok) throw new Error(data.error || "Request failed");

  return data;
}

/* =========================
   LOGIN
========================= */
async function loginAndStoreSession({ serverBase, orgId, username, password }) {
  const base = normalizeBase(serverBase);

  const res = await fetch(`${base}/auth/login`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
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
   MESSAGE ROUTER
========================= */
chrome.runtime.onMessage.addListener((msg, _, sendResponse) => {
  (async () => {
    try {

      /* LOGIN */
      if (msg.type === "QM_LOGIN") {
        await loginAndStoreSession(msg);
        sendResponse({ ok: true });
        return;
      }

      /* Recepients */
      if (msg.type === "QM_RECIPIENTS") {
        try {
          const s = await getSession();
      
          if (!s?.token || !s?.serverBase) {
            sendResponse({ ok: false, error: "Not logged in" });
            return;
          }
      
          const usersOut = await apiJson(s.serverBase, "/org/users", {
            token: s.token
          });
      
          console.log("USERS API:", usersOut);
      
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
      
        } catch (e) {
          console.error("QM_RECIPIENTS ERROR:", e);
      
          sendResponse({
            ok: false,
            error: e.message || "Failed to load users"
          });
        }
      
        return; // ✅ VERY IMPORTANT
      }
      
      /* LOAD DEVICES */
      if (msg.type === "load_devices") {
        const s = await getSession();

        const data = await apiJson(s.serverBase, "/api/devices/list", {
          token: s.token
        });

        sendResponse({ ok: true, payload: data });
        return;
      }

      /* TRUST DEVICE */
      if (msg.type === "trust_this_device") {
        const s = await getSession();

        await apiJson(s.serverBase, "/api/devices/trust", {
          method: "POST",
          token: s.token,
          body: { device_id: msg.payload.device_id }
        });

        sendResponse({ ok: true });
        return;
      }

      /* REVOKE DEVICE */
      if (msg.type === "revoke_device") {
        const s = await getSession();

        await apiJson(s.serverBase, "/api/devices/revoke", {
          method: "POST",
          token: s.token,
          body: { device_id: msg.payload.device_id }
        });

        sendResponse({ ok: true });
        return;
      }

      /* START RECOVERY */
      if (msg.type === "start_recovery") {
        const s = await getSession();

        const data = await apiJson(s.serverBase, "/api/recovery/start", {
          method: "POST",
          token: s.token
        });

        sendResponse({ ok: true, payload: data });
        return;
      }

      /* LOAD PENDING */
      if (msg.type === "load_pending") {
        const s = await getSession();

        const data = await apiJson(s.serverBase, "/api/recovery/pending", {
          token: s.token
        });

        sendResponse({ ok: true, payload: data });
        return;
      }

      /* APPROVE */
      if (msg.type === "approve_recovery") {
        const s = await getSession();

        const kp = await getOrCreateRsaKeypair(s.user.userId);
        const privateJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);

        await apiJson(s.serverBase, "/api/recovery/approve", {
          method: "POST",
          token: s.token,
          body: {
            request_id: msg.payload.request_id,
            encrypted_private_key: btoa(JSON.stringify(privateJwk))
          }
        });

        sendResponse({ ok: true });
        return;
      }

      /* FINISH */
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

        sendResponse({ ok: true });
        return;
      }


      /* =========================
           ENCRYPT
        ========================= */
        if (msg.type === "QM_ENCRYPT_SELECTION") {
          try {
            const s = await getSession();
        
            if (!s?.token || !s?.serverBase) {
              sendResponse({ ok: false, error: "Not logged in" });
              return;
            }
        
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
            const sel = await chrome.tabs.sendMessage(tab.id, {
              type: "QM_GET_SELECTION"
            });
        
            const text = String(sel?.text || "").trim();
        
            if (!text) {
              sendResponse({ ok: false, error: "No text selected" });
              return;
            }
        
            /* ENCRYPT */
            const { ctB64Url, ivB64Url, rawDek } = await aesEncrypt(text);
        
            /* LOAD DEVICES */
            const devicesRes = await apiJson(s.serverBase, "/api/devices/list", {
              token: s.token
            });
        
            const devices = devicesRes.devices || [];
        
            const wrappedKeys = {};
        
            for (const d of devices) {
              if (d.status !== "active") continue;
        
              try {
                const pub = await crypto.subtle.importKey(
                  "jwk",
                  d.pub_jwk,
                  { name: "RSA-OAEP", hash: "SHA-256" },
                  true,
                  ["encrypt"]
                );
        
                wrappedKeys[d.device_id] = await rsaWrapDek(pub, rawDek);
        
              } catch (e) {
                console.error("Key import failed:", d.device_id, e);
              }
            }
        
            if (Object.keys(wrappedKeys).length === 0) {
              sendResponse({
                ok: false,
                error: "No trusted devices available"
              });
              return;
            }
        
            /* SEND TO SERVER */
            const msgOut = await apiJson(s.serverBase, "/api/messages", {
              method: "POST",
              token: s.token,
              body: {
                iv: ivB64Url,
                ciphertext: ctB64Url,
                wrappedKeys
              }
            });
        
            /* REPLACE TEXT */
            await chrome.tabs.sendMessage(tab.id, {
              type: "QM_REPLACE_SELECTION_WITH_LINK",
              url: msgOut.url
            });
        
            sendResponse({ ok: true, payload: msgOut });
            return;
        
          } catch (e) {
            console.error("ENCRYPT ERROR:", e);
            sendResponse({ ok: false, error: e.message });
            return;
          }
          
  })();

  return true;
});
