// extension/background.js (SYNTAX FIXED — NO LOGIC REMOVED)

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

      /* RECIPIENTS */
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
          sendResponse({
            ok: false,
            error: e.message || "Failed to load users"
          });
        }

        return;
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

      /* ENCRYPT */
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

          const { ctB64Url, ivB64Url, rawDek } = await aesEncrypt(text);

          const devicesRes = await apiJson(s.serverBase, "/api/devices/list", {
            token: s.token
          });

          const devices = devicesRes.devices || [];
          console.log("DEVICES FROM API:", devices);
          const wrappedKeys = {};

          for (const d of devices) {
            if (!d.pub_jwk) continue;
          
            const status = String(d.status || "").toLowerCase().trim();
          
            if (status !== "active") {
              console.log("SKIPPING DEVICE:", d.device_id, d.status);
              continue;
            }
          
            const pub = await crypto.subtle.importKey(
              "jwk",
              d.pub_jwk,
              { name: "RSA-OAEP", hash: "SHA-256" },
              true,
              ["encrypt"]
            );
          
            wrappedKeys[d.device_id] = await rsaWrapDek(pub, rawDek);
          }
          console.log("WRAPPED KEYS:", wrappedKeys);
          if (Object.keys(wrappedKeys).length === 0) {
            sendResponse({
              ok: false,
              error: "No trusted devices available"
            });
            return;
          }

          const msgOut = await apiJson(s.serverBase, "/api/messages", {
            method: "POST",
            token: s.token,
            body: {
              iv: ivB64Url,
              ciphertext: ctB64Url,
              wrappedKeys,
              attachments: Array.isArray(msg.attachments) ? msg.attachments : []
            }
          });

          await chrome.tabs.sendMessage(tab.id, {
            type: "QM_REPLACE_SELECTION_WITH_LINK",
            url: msgOut.url
          });

          sendResponse({ ok: true, payload: msgOut });
          return;

        } catch (e) {
          sendResponse({ ok: false, error: e.message });
          return;
        }
      }



      /* =========================
           DECRYPT FLOW
        ========================= */
        if (msg.type === "QM_LOGIN_AND_DECRYPT" || msg.type === "QM_LOGIN_AND_DECRYPT_REQUEST") {
          try {
            const s = await getSession();
        
            if (!s?.token || !s?.serverBase) {
              sendResponse({ ok: false, error: "Not logged in" });
              return;
            }
        
            const base = s.serverBase;
        
            console.log("🔓 DECRYPT START:", msg.msgId);
        
            const payload = await apiJson(
              base,
              `/api/messages/${encodeURIComponent(msg.msgId)}`,
              { token: s.token }
            );
        
            const wrappedDek = payload.wrappedDek || payload.wrappedKey;
        
            if (!wrappedDek) {
              sendResponse({ ok: false, error: "Missing wrapped key" });
              return;
            }
        
            const kp = await getOrCreateRsaKeypair(s.user.userId);
        
            let rawDek;
            try {
              rawDek = await crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                kp.privateKey,
                Uint8Array.from(atob(wrappedDek), c => c.charCodeAt(0))
              );
            } catch (e) {
              sendResponse({
                ok: false,
                error: "Device key mismatch. Re-encrypt message."
              });
              return;
            }
        
            const plaintext = await aesDecrypt(
              payload.iv,
              payload.ciphertext,
              payload.aad,
              new Uint8Array(rawDek)
            );
        
            console.log("✅ DECRYPT SUCCESS");
        
            sendResponse({
              ok: true,
              plaintext,
              attachments: payload.attachments || []
            });
        
          } catch (e) {
            console.error("❌ DECRYPT ERROR:", e);
            sendResponse({ ok: false, error: e.message });
          }
        
          return;
        }
      /* DEFAULT */
      sendResponse({ ok: false });

    } catch (e) {
      sendResponse({ ok: false, error: e.message });
    }
  })();

  return true;
});
