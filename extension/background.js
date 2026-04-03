// extension/background.js (FINAL — ATTACHMENTS + FIXES, NOTHING REMOVED)

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
import { deriveKek, storeKek } from "./qm.js";

/* =========================
   HELPERS
========================= */
function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function unb64(s) {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

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

  const text = await res.text();

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    console.error("❌ API returned HTML:", text.slice(0, 200));
    throw new Error("Invalid server response");
  }
  
  if (!res.ok) throw new Error(data.error || "Request failed");

  return data;
}

/* =========================
   LOGIN
========================= */
async function loginAndStoreSession({ serverBase, orgId, username, password }) {
  const base = normalizeBase(serverBase);
  const kek = await deriveKek(password);
  await storeKek(kek);
  const res = await fetch(`${base}/auth/login`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ orgId, username, password })
  });

  console.log("📡 LOGIN URL:", res.url);
  console.log("📡 STATUS:", res.status);

  const text = await res.text();

  let data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    console.error("❌ Non-JSON response:", text.slice(0, 300));
    throw new Error("Server returned HTML instead of JSON");
  }

  if (!res.ok) {
    throw new Error(data.error || "Login failed");
  }

  if (!data.token) {
    throw new Error("Invalid login response");
  }

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

      /* =========================
           START RECOVERY
        ========================= */
        if (msg.type === "QM_START_RECOVERY") {
          const s = await getSession();
        
          const data = await apiJson(s.serverBase, "/api/recovery/start", {
            method: "POST",
            token: s.token
          });
        
          sendResponse({ ok: true, payload: data });
          return;
        }
        
        /* =========================
           LOAD PENDING REQUESTS
        ========================= */
        if (msg.type === "QM_LOAD_RECOVERY_PENDING") {
          const s = await getSession();
        
          const data = await apiJson(s.serverBase, "/api/recovery/pending", {
            token: s.token
          });
        
          sendResponse({ ok: true, payload: data });
          return;
        }
        
        /* =========================
           APPROVE RECOVERY (OTHER DEVICE)
        ========================= */
        if (msg.type === "QM_APPROVE_RECOVERY") {
          const s = await getSession();
        
          const kp = await getOrCreateRsaKeypair(s.user.userId);
          const privateJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
        
          const data = await apiJson(s.serverBase, "/api/recovery/approve", {
            method: "POST",
            token: s.token,
            body: {
              request_id: msg.requestId,
              encrypted_private_key: btoa(JSON.stringify(privateJwk))
            }
          });
        
          sendResponse({ ok: true, payload: data });
          return;
        }
        
        /* =========================
           FINISH RECOVERY
        ========================= */
        if (msg.type === "QM_FINISH_RECOVERY") {
          const s = await getSession();
        
          const data = await apiJson(
            s.serverBase,
            `/api/recovery/finish/${msg.requestId}`,
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
         ENCRYPT (FIXED)
      ========================= */
      if (msg.type === "QM_ENCRYPT_SELECTION") {
        try {
          const s = await getSession();

          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

          const sel = await chrome.tabs.sendMessage(tab.id, {
            type: "QM_GET_SELECTION"
          });

          const text = String(sel?.text || "").trim();
          if (!text) return sendResponse({ ok: false, error: "No text selected" });

          const { ctB64Url, ivB64Url, rawDek } = await aesEncrypt(text);

          const devicesRes = await apiJson(s.serverBase, "/api/devices/list", {
            token: s.token
          });

          const wrappedKeys = {};

          for (const d of devicesRes.devices || []) {
            if (!d.pub_jwk) continue;
            if (String(d.status).toLowerCase() !== "active") continue;

            const pub = await crypto.subtle.importKey(
              "jwk",
              d.pub_jwk,
              { name: "RSA-OAEP", hash: "SHA-256" },
              true,
              ["encrypt"]
            );

            wrappedKeys[d.device_id] = await rsaWrapDek(pub, rawDek);
          }

          if (!Object.keys(wrappedKeys).length) {
            return sendResponse({ ok: false, error: "No trusted devices available" });
          }

          /* 🔥 ENCRYPT ATTACHMENTS */
          const encryptedAttachments = [];

          for (const file of msg.attachments || []) {
            const iv = crypto.getRandomValues(new Uint8Array(12));

            const key = await crypto.subtle.importKey("raw", rawDek, "AES-GCM", false, ["encrypt"]);

            const ct = await crypto.subtle.encrypt(
              { name: "AES-GCM", iv },
              key,
              new Uint8Array(file.bytes)
            );

            encryptedAttachments.push({
              name: file.name,
              mimeType: file.mimeType,
              size: file.size,
              iv: b64(iv),
              ciphertext: b64(ct)
            });
          }

          const msgOut = await apiJson(s.serverBase, "/api/messages", {
            method: "POST",
            token: s.token,
            body: {
              iv: ivB64Url,
              ciphertext: ctB64Url,
              wrappedKeys,
              attachments: encryptedAttachments
            }
          });

          await chrome.tabs.sendMessage(tab.id, {
            type: "QM_REPLACE_SELECTION_WITH_LINK",
            url: msgOut.url
          });

          sendResponse({ ok: true, payload: msgOut });

        } catch (e) {
          sendResponse({ ok: false, error: e.message });
        }

        return;
      }

      if (msg.type === "QM_RESTORE_KEY") {
        try {
          const s = await getSession();
      
          console.log("🔑 Restoring key...");
      
          await chrome.storage.local.set({
            [`qm_rsa_${s.user.userId}`]: msg.payload
          });
      
          console.log("✅ Key restored");
      
          sendResponse({ ok: true });
      
        } catch (e) {
          console.error("❌ Restore failed:", e);
      
          sendResponse({
            ok: false,
            error: e.message
          });
        }
      
        return;
      }

      
      if (msg.type === "QM_REWRAP_MESSAGE") {
        try {
          const { messageId, payload } = msg;
      
          /* =========================
             🔥 FIX 1: Normalize payload
          ========================= */
          if (!payload?.wrappedKeys && payload?.wrappedDek) {
            console.warn("⚠️ Legacy message detected:", messageId);
      
            payload.wrappedKeys = {
              legacy: payload.wrappedDek
            };
          }
      
          /* =========================
             🔥 FIX 2: HARD GUARD (NO CRASH)
          ========================= */
          if (!payload?.wrappedKeys || Object.keys(payload.wrappedKeys).length === 0) {
            console.warn("⚠️ Skipping message (no wrappedKeys):", messageId);
      
            return sendResponse({
              ok: true,
              skipped: true,
              reason: "NO_WRAPPED_KEYS"
            });
          }
      
          const session = await getSession();
      
          if (!session?.user?.userId) {
            return sendResponse({ ok: false, error: "No session" });
          }
      
          const deviceId = await getDeviceId();
      
          /* =========================
             🔥 FIX 3: Already wrapped?
          ========================= */
          if (payload.wrappedKeys[deviceId]) {
            console.log("⏭️ Already wrapped:", messageId);
            return sendResponse({ ok: true });
          }
      
          /* =========================
             🔐 STEP 1: FIND VALID KEY
          ========================= */
          const availableWrappedKeys = Object.entries(payload.wrappedKeys)
            .filter(([id]) => id !== deviceId)
            .map(([, wk]) => wk);
      
          if (!availableWrappedKeys.length) {
            console.warn("⚠️ No usable wrapped keys:", messageId);
            return sendResponse({ ok: true, skipped: true });
          }
      
          let dek;

          /* =========================
             🔐 ZERO TRUST VAULT FLOW
          ========================= */
          if (msg.vault?.enc_wk_b64 && msg.vault?.iv_b64) {
            console.log("🔐 Using vault sealed key");
          
            try {
              const encWrappedKey = Uint8Array.from(
                atob(msg.vault.enc_wk_b64),
                c => c.charCodeAt(0)
              );
          
              const iv = Uint8Array.from(
                atob(msg.vault.iv_b64),
                c => c.charCodeAt(0)
              );
          
              const kek = await getKek();
          
              const wrappedKey = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv },
                kek,
                encWrappedKey
              );
          
              dek = new Uint8Array(wrappedKey);
          
              console.log("✅ DEK recovered from vault");
          
            } catch (e) {
              console.error("❌ Vault decrypt failed:", e);
              return sendResponse({ ok: false, error: "Vault decryption failed" });
            }
          }
          
          /* =========================
             FALLBACK (OLD DEVICES)
          ========================= */
          if (!dek) {
            console.warn("⚠️ Falling back to existing wrappedKeys");
          
            for (const wk of availableWrappedKeys) {
              try {
                dek = await rsaUnwrapDek(wk);
                break;
              } catch (e) {
                continue;
              }
            }
          
            if (!dek) {
              return sendResponse({ ok: false, error: "Cannot unwrap DEK" });
            }
          }
      
          /* =========================
             🔐 STEP 2: WRAP FOR DEVICE
          ========================= */
          const devices = await apiJson(
            session.serverBase,
            "/api/devices/list",
            { token: session.token }
          );
          
          const device = devices.devices.find(d => d.device_id === deviceId);
          
          if (!device || !device.pub_jwk) {
            return sendResponse({ ok: false, error: "Device public key not found" });
          }
          
          const publicKey = await crypto.subtle.importKey(
            "jwk",
            device.pub_jwk,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["encrypt"]
          );
      
          const newWrappedKey = await rsaWrapDek(publicKey, dek);
      
          /* =========================
             🔐 STEP 3: SEND TO SERVER
          ========================= */
          const res = await fetch(
            `${session.serverBase}/api/messages/${messageId}/add-device-key`,
            {
              method: "POST",
              headers: {
                Authorization: `Bearer ${session.token}`,
                "Content-Type": "application/json",
                "x-qm-device-id": deviceId
              },
              body: JSON.stringify({
                wrappedKey: newWrappedKey
              })
            }
          );
      
          if (!res.ok) {
            const errText = await res.text();
            console.error("❌ Server error:", errText);
            return sendResponse({ ok: false, error: errText });
          }
      
          console.log("✅ Rewrap success:", messageId);
      
          return sendResponse({ ok: true });
      
        } catch (e) {
          console.error("❌ REWRAP ERROR:", e);
      
          return sendResponse({
            ok: false,
            error: e.message
          });
        }
      }
      
      /* =========================
         DECRYPT (FIXED)
      ========================= */
      if (msg.type === "QM_LOGIN_AND_DECRYPT_REQUEST" || msg.type === "QM_LOGIN_AND_DECRYPT") {
        try {
          const s = await getSession();

          const payload = await apiJson(
            s.serverBase,
            `/api/messages/${msg.msgId}`,
            { token: s.token }
          );

          const wrappedDek = payload.wrappedDek;
          const kp = await getOrCreateRsaKeypair(s.user.userId);

          const rawDek = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            kp.privateKey,
            unb64(wrappedDek)
          );

          const dek = new Uint8Array(rawDek);

          const plaintext = await aesDecrypt(
            payload.iv,
            payload.ciphertext,
            payload.aad,
            dek
          );

          /* 🔥 DECRYPT ATTACHMENTS */
          const decryptedAttachments = [];

          for (const a of payload.attachments || []) {
            const iv = unb64(a.iv);
            const ct = unb64(a.ciphertext);

            const key = await crypto.subtle.importKey("raw", dek, "AES-GCM", false, ["decrypt"]);

            const pt = await crypto.subtle.decrypt(
              { name: "AES-GCM", iv },
              key,
              ct
            );

            decryptedAttachments.push({
              name: a.name,
              mimeType: a.mimeType,
              size: a.size,
              bytes: Array.from(new Uint8Array(pt))
            });
          }

          sendResponse({
            ok: true,
            plaintext,
            attachments: decryptedAttachments
          });

        } catch (e) {
          sendResponse({ ok: false, error: e.message });
        }

        return;
      }

      sendResponse({ ok: false });

    } catch (e) {
      sendResponse({ ok: false, error: e.message });
    }
  })();

  return true;
});
