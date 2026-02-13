// extension/qm.js

export const DEFAULTS = {
  serverBase: "",
  token: "",
  user: null
};

export function normalizeBase(url) {
  return String(url || "").replace(/\/+$/, "");
}

export async function getSession() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(DEFAULTS, (v) => resolve(v || DEFAULTS));
  });
}

export async function setSession(patch) {
  return new Promise((resolve) => {
    chrome.storage.sync.set(patch, () => resolve());
  });
}

export async function clearSession() {
  return setSession({ ...DEFAULTS });
}

export function parseRecipients(input) {
  return String(input || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

// ---------- Base64 helpers ----------
export function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function bytesToB64Url(bytes) {
  return bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function b64UrlToBytes(b64url) {
  let b64 = String(b64url || "").replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return b64ToBytes(b64);
}

// ---------- Crypto primitives ----------
export async function getOrCreateRsaKeypair() {
  const existing = await new Promise((resolve) => {
    chrome.storage.local.get({ qm_rsa: null }, (v) => resolve(v.qm_rsa));
  });

  if (existing?.privateJwk && existing?.publicJwk) {
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      existing.privateJwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["decrypt"]
    );
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      existing.publicJwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["encrypt"]
    );
    return { privateKey, publicKey };
  }

  const kp = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );

  const privateJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const publicJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);

  await new Promise((resolve) => {
    chrome.storage.local.set({ qm_rsa: { privateJwk, publicJwk } }, () => resolve());
  });

  return { privateKey: kp.privateKey, publicKey: kp.publicKey };
}

export async function exportPublicSpkiB64(publicKey) {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  return bytesToB64(new Uint8Array(spki));
}

export async function importPublicSpkiB64(publicKeySpkiB64) {
  const spkiBytes = b64ToBytes(publicKeySpkiB64);
  return crypto.subtle.importKey(
    "spki",
    spkiBytes,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
}

/**
 * Register user's public key with server so others can wrap DEKs for them.
 * Server endpoint (new): POST /org/register-key
 * Back-compat endpoint: POST /pubkey_register (optional alias)
 */
export async function ensureKeypairAndRegister(serverBase, token) {
  const { publicKey } = await getOrCreateRsaKeypair();
  const publicKeySpkiB64 = await exportPublicSpkiB64(publicKey);

  async function tryRegister(path) {
    const res = await fetch(`${serverBase}${path}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ publicKeySpkiB64 })
    });

    const data = await res.json().catch(() => ({}));
    return { res, data };
  }

  // 1) Preferred endpoint
  let out = await tryRegister("/org/register-key");
  if (out.res.ok) return;

  // 2) Back-compat alias
  out = await tryRegister("/pubkey_register");
  if (out.res.ok) return;

  throw new Error(out.data?.error || `pubkey_register failed (${out.res.status})`);
}

// AES-GCM envelope encryption
export async function aesEncrypt(plaintext, aadText = "gmail") {
  const dek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt"
  ]);

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ptBytes = new TextEncoder().encode(plaintext);
  const aadBytes = new TextEncoder().encode(aadText);

  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aadBytes },
    dek,
    ptBytes
  );

  const rawDek = new Uint8Array(await crypto.subtle.exportKey("raw", dek));
  return {
    ivB64Url: bytesToB64Url(iv),
    ctB64Url: bytesToB64Url(new Uint8Array(ct)),
    aad: aadText,
    rawDek
  };
}

export async function aesDecrypt(ivB64Url, ctB64Url, aadText, rawDekBytes) {
  const iv = b64UrlToBytes(ivB64Url);
  const ct = b64UrlToBytes(ctB64Url);
  const aadBytes = new TextEncoder().encode(aadText || "");

  const dek = await crypto.subtle.importKey("raw", rawDekBytes, { name: "AES-GCM" }, false, [
    "decrypt"
  ]);

  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aadBytes },
    dek,
    ct
  );

  return new TextDecoder().decode(pt);
}

export async function rsaWrapDek(recipientPublicKey, rawDekBytes) {
  const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientPublicKey, rawDekBytes);
  return bytesToB64Url(new Uint8Array(wrapped));
}
