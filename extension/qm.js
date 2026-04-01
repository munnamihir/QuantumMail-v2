// =========================
// DEFAULTS
// =========================
export const DEFAULTS = {
  serverBase: "",
  token: "",
  user: null
};

// =========================
// DEVICE ID (STABLE)
// =========================
export async function getDeviceId() {
  const { deviceId } = await chrome.storage.local.get("deviceId");

  if (deviceId) return deviceId;

  const newId = "d_" + crypto.randomUUID().replace(/-/g, "");

  await chrome.storage.local.set({ deviceId: newId });

  console.log("NEW DEVICE ID:", newId);
  return newId;
}

// =========================
// BASE URL
// =========================
export function normalizeBase(url) {
  let s = String(url || "").trim();
  if (s && !/^https?:\/\//i.test(s)) s = "https://" + s;
  return s.replace(/\/+$/, "");
}

// =========================
// SESSION
// =========================
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

// =========================
// API (CRITICAL FIX)
// =========================
export async function apiJson(serverBase, path, { method = "GET", token = "", body = null } = {}) {
  const base = normalizeBase(serverBase);
  const url = base + path;

  const headers = {
    "Content-Type": "application/json"
  };

  if (token) headers.Authorization = `Bearer ${token}`;

  const deviceId = await getDeviceId();
  if (deviceId) headers["x-qm-device-id"] = deviceId;

  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });

  const raw = await res.text().catch(() => "");
  let data;

  try {
    data = JSON.parse(raw);
  } catch {
    data = raw;
  }

  if (!res.ok) {
    throw new Error(data?.error || `HTTP ${res.status}`);
  }

  return data;
}

// =========================
// RSA STORAGE (FIXED)
// =========================
function rsaStorageKey(deviceId) {
  return `qm_rsa_${deviceId}`;
}

// =========================
// RSA KEYS (DEVICE-BOUND)
// =========================
export async function getOrCreateRsaKeypair(userId) {
  // 🔥 IMPORTANT FIX: use deviceId instead of userId
  const deviceId = await getDeviceId();

  const key = rsaStorageKey(deviceId);

  const existing = await new Promise((resolve) => {
    chrome.storage.local.get(key, (v) => resolve(v[key]));
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
      { [key]: { privateJwk, publicJwk } },
      () => resolve()
    );
  });

  console.log("🔐 New keypair created for device:", deviceId);

  return kp;
}

// =========================
// AES ENCRYPT
// =========================
export async function aesEncrypt(plaintext, aadText = "web") {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );

  const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));

  return {
    ivB64Url: btoa(String.fromCharCode(...iv)),
    ctB64Url: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    rawDek: rawKey
  };
}

// =========================
// AES DECRYPT
// =========================
export async function aesDecrypt(ivB64, ctB64, aad, rawKey) {
  const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
  const ct = Uint8Array.from(atob(ctB64), c => c.charCodeAt(0));

  const key = await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ct
  );

  return new TextDecoder().decode(decrypted);
}

// =========================
// RSA WRAP
// =========================
export async function rsaWrapDek(publicKey, rawDek) {
  const wrapped = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    rawDek
  );

  return btoa(String.fromCharCode(...new Uint8Array(wrapped)));
}

// =========================
// DEVICE REGISTER (UNCHANGED)
// =========================
export async function ensureDeviceRegistered(serverBase, token, userId) {
  const deviceId = await getDeviceId();

  const { publicKey } = await getOrCreateRsaKeypair(userId);
  const pubJwk = await crypto.subtle.exportKey("jwk", publicKey);

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
      pub_jwk: pubJwk,
      label: "Chrome Extension",
      device_type: "desktop"
    })
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    console.error("REGISTER FAILED:", data);
    throw new Error("Device registration failed");
  }

  return data;
}
