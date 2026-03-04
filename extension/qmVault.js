// extension/qmVault.js
import { apiJson } from "./qm.js"; // your existing helper
// If you don't have apiJson, we can add it; you already do in your repo.

function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}
function unb64(s) {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
async function sha256Hex(str) {
  const buf = new TextEncoder().encode(str);
  const h = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(h)].map(x => x.toString(16).padStart(2, "0")).join("");
}

async function hkdfKeyFromToken(tokenId, tokenSecret) {
  // HKDF-SHA256 -> AES-GCM key
  const ikm = new TextEncoder().encode(tokenSecret);
  const salt = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("qm-recovery|" + tokenId));

  const baseKey = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("qm-wk-wrap-v1") },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function aesGcmEncrypt(key, plaintextBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintextBytes);
  // WebCrypto returns ct||tag combined
  return { iv, ct: new Uint8Array(ct) };
}

async function aesGcmDecrypt(key, iv, ctBytes) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ctBytes);
  return new Uint8Array(pt);
}

async function getLocal(key) {
  return new Promise(resolve => chrome.storage.local.get([key], r => resolve(r[key] || null)));
}
async function setLocal(obj) {
  return new Promise(resolve => chrome.storage.local.set(obj, resolve));
}

/**
 * Ensure WK exists (32 bytes). Return WK bytes.
 */
export async function ensureWrapKey() {
  const wkB64 = await getLocal("qm_wk_b64");
  if (wkB64) return unb64(wkB64);

  const wk = crypto.getRandomValues(new Uint8Array(32));
  await setLocal({ qm_wk_b64: b64(wk) });
  return wk;
}

/**
 * Setup recovery vault:
 * - token_id from server
 * - token_secret generated here (never sent to server)
 * - encrypt WK with HKDF(token) derived key
 * - upload encrypted blob to portal
 */
export async function setupRecoveryVault(apiBase) {
  const init = await apiJson(apiBase, "/api/recovery/init", { method: "POST", body: {} });
  const token_id = init.token_id;

  // generate secret (user must save)
  const secretBytes = crypto.getRandomValues(new Uint8Array(32));
  const token_secret = b64(secretBytes).replace(/=+$/,""); // user-facing

  const wk = await ensureWrapKey();
  const key = await hkdfKeyFromToken(token_id, token_secret);

  const { iv, ct } = await aesGcmEncrypt(key, wk);

  // token verifier (server stores; still useless to decrypt)
  const token_verifier_hash = await sha256Hex("qm|"+token_id+"|"+token_secret);

  await apiJson(apiBase, "/api/recovery/vault", {
    method: "PUT",
    body: {
      token_id,
      token_verifier_hash,
      enc_wk_b64: b64(ct),
      iv_b64: b64(iv),
      tag_b64: "" , // not needed separately in WebCrypto format (ct includes tag)
      wk_version: 1
    }
  });

  await setLocal({
    qm_token_id: token_id,
    qm_token_verifier_hash: token_verifier_hash
  });

  // Return token for user to save ONCE
  return { token_id, token_secret, display: `qm-rrt-1|${token_id}|${token_secret}` };
}

/**
 * Recover WK from portal using token string.
 */
export async function recoverWrapKeyFromVault(apiBase, tokenString) {
  // token format: qm-rrt-1|token_id|token_secret
  const parts = String(tokenString || "").split("|");
  if (parts.length !== 3) throw new Error("Bad token format. Expected: qm-rrt-1|token_id|token_secret");
  const token_id = parts[1];
  const token_secret = parts[2];

  const vault = await apiJson(apiBase, "/api/recovery/vault", { method: "GET" });
  if (vault.token_id !== token_id) throw new Error("Token ID mismatch for this account.");

  const key = await hkdfKeyFromToken(token_id, token_secret);

  const wk = await aesGcmDecrypt(key, unb64(vault.iv_b64), unb64(vault.enc_wk_b64));
  if (wk.length !== 32) throw new Error("Recovered WK has wrong length.");

  await setLocal({ qm_wk_b64: b64(wk) });
  return true;
}
