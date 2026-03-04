// extension/qmVault.js
import { apiJson } from "./qm.js";

/**
 * Token + 1 device quorum recovery
 *
 * - Device has an Ed25519 signing keypair used ONLY to approve recoveries.
 * - Vault stores WK encrypted with token-derived AES-GCM key.
 * - Recovery requires:
 *   (a) token proof (token_verifier_hash)
 *   (b) approval signature from another trusted device
 */

async function ensureLocalDeviceIdOnly() {
  const existing = await getLocal("qm_device_id");
  if (existing) return existing;
  const device_id = randId("d_");
  await setLocal({ qm_device_id: device_id });
  return device_id;
}

export async function getPendingRecovery(apiBase) {
  // expected to return { request_id, nonce_b64 } or null
  const out = await apiJson(apiBase, "/api/recovery/quorum/pending", { method: "GET" });
  if (!out || !out.request_id) return null;
  return { request_id: out.request_id, nonce_b64: out.nonce_b64 };
}

function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}
function unb64(s) {
  return Uint8Array.from(atob(String(s || "")), (c) => c.charCodeAt(0));
}

async function sha256Hex(str) {
  const buf = new TextEncoder().encode(str);
  const h = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function hkdfKeyFromToken(tokenId, tokenSecret) {
  const ikm = new TextEncoder().encode(tokenSecret);
  const salt = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("qm-recovery|" + tokenId));
  const baseKey = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("qm-wk-wrap-v2") },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function aesGcmEncrypt(key, plaintextBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintextBytes);
  return { iv, ct: new Uint8Array(ct) };
}

async function aesGcmDecrypt(key, iv, ctBytes) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ctBytes);
  return new Uint8Array(pt);
}

async function getLocal(key) {
  return new Promise((resolve) => chrome.storage.local.get([key], (r) => resolve(r[key] ?? null)));
}
async function setLocal(obj) {
  return new Promise((resolve) => chrome.storage.local.set(obj, resolve));
}

function randId(prefix) {
  const b = crypto.getRandomValues(new Uint8Array(12));
  return prefix + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

/** =========================
 * Device keypair (Ed25519)
 * ========================= */
async function ensureDeviceIdentity(apiBase) {
  const existing = await getLocal("qm_device_id");
  const jwkPriv = await getLocal("qm_device_priv_jwk");
  const jwkPub = await getLocal("qm_device_pub_jwk");

  if (existing && jwkPriv && jwkPub) return { device_id: existing, priv_jwk: jwkPriv, pub_jwk: jwkPub };

  const device_id = randId("d_");
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const priv_jwk_new = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pub_jwk_new = await crypto.subtle.exportKey("jwk", kp.publicKey);

  await setLocal({
    qm_device_id: device_id,
    qm_device_priv_jwk: priv_jwk_new,
    qm_device_pub_jwk: pub_jwk_new
  });

  // Register with server
  await apiJson(apiBase, "/api/devices/register", {
    method: "POST",
    body: { device_id, label: navigator.userAgent.slice(0, 64), pub_jwk: pub_jwk_new }
  });

  return { device_id, priv_jwk: priv_jwk_new, pub_jwk: pub_jwk_new };
}

async function signWithDevice(priv_jwk, msg) {
  const priv = await crypto.subtle.importKey("jwk", priv_jwk, { name: "Ed25519" }, false, ["sign"]);
  const msgBytes = new TextEncoder().encode(msg);
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, priv, msgBytes);
  return b64(new Uint8Array(sig));
}

/** =========================
 * Wrap Key (WK) storage
 * ========================= */
export async function ensureWrapKey() {
  const wkB64 = await getLocal("qm_wk_b64");
  if (wkB64) return unb64(wkB64);

  const wk = crypto.getRandomValues(new Uint8Array(32));
  await setLocal({ qm_wk_b64: b64(wk) });
  return wk;
}

/** =========================
 * Enable vault (token created)
 * ========================= */
export async function setupRecoveryVault(apiBase) {
  // ensure this device is registered
  await ensureDeviceIdentity(apiBase);

  const init = await apiJson(apiBase, "/api/recovery/init", { method: "POST", body: {} });
  const token_id = init.token_id;

  const secretBytes = crypto.getRandomValues(new Uint8Array(32));
  const token_secret = b64(secretBytes).replace(/=+$/, "");

  const wk = await ensureWrapKey();
  const key = await hkdfKeyFromToken(token_id, token_secret);
  const { iv, ct } = await aesGcmEncrypt(key, wk);

  const token_verifier_hash = await sha256Hex("qm|v2|" + token_id + "|" + token_secret);

  await apiJson(apiBase, "/api/recovery/vault", {
    method: "PUT",
    body: {
      token_id,
      token_verifier_hash,
      enc_wk_b64: b64(ct),
      iv_b64: b64(iv),
      wk_version: 2
    }
  });

  await setLocal({
    qm_token_id: token_id,
    qm_token_verifier_hash: token_verifier_hash
  });

  return {
    token_id,
    token_secret,
    display: `qm-rrt-2|${token_id}|${token_secret}`
  };
}

/** =========================
 * Start recovery (token + request)
 * ========================= */
export async function startRecoveryRequest(apiBase, tokenString) {
  const parts = String(tokenString || "").split("|");
  if (parts.length !== 3 || parts[0] !== "qm-rrt-2") {
    throw new Error("Bad token format. Expected: qm-rrt-2|token_id|token_secret");
  }
  const token_id = parts[1];
  const token_secret = parts[2];

  const device_id = await ensureLocalDeviceIdOnly();
  const token_verifier_hash = await sha256Hex("qm|v2|" + token_id + "|" + token_secret);

  const out = await apiJson(apiBase, "/api/recovery/quorum/start", {
    method: "POST",
    body: { token_id, token_verifier_hash, requester_device_id: device_id }
  });

  return { request_id: out.request_id, nonce_b64: out.nonce_b64, token_id, token_secret };
}

/** =========================
 * Approve recovery (on trusted device)
 * ========================= */
export async function approveRecoveryRequest(apiBase, request_id, nonce_b64) {
  const ident = await ensureDeviceIdentity(apiBase);

  const msg = `qm-recover-v1|${request_id}|${nonce_b64}`;
  const sig_b64 = await signWithDevice(ident.priv_jwk, msg);

  await apiJson(apiBase, "/api/recovery/quorum/approve", {
    method: "POST",
    body: { request_id, device_id: ident.device_id, sig_b64 }
  });

  return true;
}

/** =========================
 * Fetch + recover WK (after approval)
 * ========================= */
export async function finishRecoveryFetch(apiBase, request_id, token_id, token_secret) {
  const token_verifier_hash = await sha256Hex("qm|v2|" + token_id + "|" + token_secret);

  const out = await apiJson(apiBase, "/api/recovery/quorum/fetch", {
    method: "POST",
    body: { request_id, token_id, token_verifier_hash }
  });

  const v = out.vault;
  const key = await hkdfKeyFromToken(v.token_id, token_secret);
  const wk = await aesGcmDecrypt(key, unb64(v.iv_b64), unb64(v.enc_wk_b64));
  if (wk.length !== 32) throw new Error("Recovered WK has wrong length.");

  await setLocal({ qm_wk_b64: b64(wk) });
  await ensureDeviceIdentity(apiBase);
  return true;
}

/** Convenience: one-call recover (start -> wait -> fetch) handled by portal UI */
