// extension/qm.js

export const DEFAULTS = {
  serverBase: "",
  token: "",
  user: null
};

/* =========================================================
   DEVICE ID (stable per browser)
========================================================= */
export async function getDeviceId() {
  const { deviceId } = await chrome.storage.local.get("deviceId");

  if (deviceId) return deviceId;

  const newId = "d_" + crypto.randomUUID().replace(/-/g, "");
  await chrome.storage.local.set({ deviceId: newId });

  console.log("NEW DEVICE ID CREATED:", newId);
  return newId;
}

/* =========================================================
   SESSION
========================================================= */
export function normalizeBase(url) {
  let s = String(url || "").trim();
  if (s && !/^https?:\/\//i.test(s)) s = "https://" + s;
  return s.replace(/\/+$/, "");
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

/* =========================================================
   API HELPER (with device binding)
========================================================= */
export async function apiJson(apiBase, path, opts = {}) {
  const base = normalizeBase(apiBase);
  const url = base + path;

  const session = await getSession();
  const token = String(session?.token || "").trim();

  if (!token) {
    throw new Error("Missing Bearer token. Login first.");
  }

  const deviceId = await getDeviceId();

  const res = await fetch(url, {
    method: opts.method || "GET",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      "x-qm-device-id": deviceId,
      ...(opts.headers || {})
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });

  const raw = await res.text().catch(() => "");
  let data;

  try {
    data = (res.headers.get("content-type") || "").includes("application/json")
      ? JSON.parse(raw || "{}")
      : raw;
  } catch {
    data = raw;
  }

  if (!res.ok) {
    throw new Error(`HTTP ${res.status}: ${typeof data === "string" ? data : JSON.stringify(data)}`);
  }

  return data;
}

/* =========================================================
   BASE64 HELPERS
========================================================= */
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
  return bytesToB64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function b64UrlToBytes(b64url) {
  let b64 = String(b64url || "").replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return b64ToBytes(b64);
}

/* =========================================================
   RSA KEY MANAGEMENT (JWK BASED)
========================================================= */
function rsaStorageKey(userId) {
  return `qm_rsa_${userId}`;
}

export async function getOrCreateRsaKeypair(userId) {
  const key = rsaStorageKey(userId);

  const existing = await new Promise((resolve) => {
    chrome.storage.local.get({ [key]: null }, (v) => resolve(v[key]));
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
    chrome.storage.local.set(
      {
        [key]: {
          privateJwk,
          publicJwk,
          createdAt: new Date().toISOString()
        }
      },
      () => resolve()
    );
  });

  return { privateKey: kp.privateKey, publicKey: kp.publicKey };
}

/* =========================================================
   DEVICE REGISTRATION (JWK)
========================================================= */
export async function ensureKeypairAndRegister(serverBase, token, userId) {
  const { publicKey } = await getOrCreateRsaKeypair(userId);
  const publicJwk = await crypto.subtle.exportKey("jwk", publicKey);

  const deviceId = await getDeviceId();

  console.log("REGISTER DEVICE:", deviceId);

  const res = await fetch(`${serverBase}/api/devices/register`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "x-qm-device-id": deviceId
    },
    body: JSON.stringify({
      device_id: deviceId,
      pub_jwk: publicJwk,
      label: "Chrome Extension",
      device_type: "desktop"
    })
  });

  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    console.error("REGISTER FAILED:", txt);
    throw new Error("Device registration failed");
  }
}

/* =========================================================
   AES-GCM ENCRYPTION
========================================================= */
export async function aesEncrypt(plaintext, aadText = "gmail") {
  const dek = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

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

/* =========================================================
   AES-GCM DECRYPTION
========================================================= */
export async function aesDecrypt(ivB64Url, ctB64Url, aadText, rawDekBytes) {
  const iv = b64UrlToBytes(ivB64Url);
  const ct = b64UrlToBytes(ctB64Url);
  const aadBytes = new TextEncoder().encode(aadText || "");

  const dek = await crypto.subtle.importKey(
    "raw",
    rawDekBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aadBytes },
    dek,
    ct
  );

  return new TextDecoder().decode(pt);
}

/* =========================================================
   RSA WRAP DEK
========================================================= */
export async function rsaWrapDek(publicKey, rawDekBytes) {
  const wrapped = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    rawDekBytes
  );

  return bytesToB64Url(new Uint8Array(wrapped));
}
