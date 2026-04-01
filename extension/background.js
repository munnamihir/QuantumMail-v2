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

      /* =========================
         DECRYPT (FIXED)
      ========================= */
      if (msg.type === "QM_LOGIN_AND_DECRYPT_REQUEST") {
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
