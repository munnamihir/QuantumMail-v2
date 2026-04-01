// =========================
// DEFAULTS
// =========================
export const DEFAULTS = {
  serverBase: "",
  token: "",
  user: null
};

// =========================
// DEVICE ID
// =========================
export async function getDeviceId() {
  const stored = await chrome.storage.local.get("qm_device_id");

  if (stored.qm_device_id) return stored.qm_device_id;

  const id = "dev_" + crypto.randomUUID();

  await chrome.storage.local.set({ qm_device_id: id });

  return id;
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
// RSA KEYS
// =========================
function rsaStorageKey(userId) {
  return `qm_rsa_${userId}`;
}

export async function getOrCreateRsaKeypair(deviceId) {
  const keyName = `qm_rsa_${deviceId}`;

  const stored = await chrome.storage.local.get(keyName);

  if (stored[keyName]) return stored[keyName];

  const keypair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );

  const jwk = await crypto.subtle.exportKey("jwk", keypair.privateKey);

  await chrome.storage.local.set({ [keyName]: jwk });

  return jwk;
}

// =========================
// AES
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
    ivB64Url: btoa(String.fromCharCode(...iv)),              // ✅ FIXED NAME
    ctB64Url: btoa(String.fromCharCode(...new Uint8Array(ciphertext))), // ✅ FIXED NAME
    rawDek: rawKey
  };
}

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
// DEVICE REGISTER (PENDING)
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
