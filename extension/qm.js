// extension/qm.js

export const DEFAULTS = {
  serverBase: "",
  token: "",
  user: null
};

export async function getDeviceId() {
  const { deviceId } = await chrome.storage.local.get("deviceId");

  if (deviceId) return deviceId;

  const newId = "d_" + crypto.randomUUID().replace(/-/g, "");

  await chrome.storage.local.set({ deviceId: newId });

  console.log("NEW DEVICE ID CREATED:", newId);

  return newId;
}

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

export async function apiJson(apiBase, path, opts = {}) {
  const base = normalizeBase(apiBase);
  const url = base + path;

  const session = await getSession();
  const token = String(session?.token || "").trim();

  if (!token) {
    throw new Error("Missing Bearer token. Login first so session.token is set.");
  }

  const deviceId = await getDeviceId(); // ✅ NEW
  console.log("DEVICE ID:", deviceId);
  const res = await fetch(url, {
    method: opts.method || "GET",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      "x-qm-device-id": deviceId, // ✅ CRITICAL FIX
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

function rsaStorageKey(userId) {
  const id = String(userId || "").trim();
  if (!id) return null;
  return `qm_rsa_${id}`;
}

export async function getOrCreateRsaKeypair(userId) {
  const key = rsaStorageKey(userId);
  if (!key) throw new Error("Missing userId for RSA keypair.");

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
      { [key]: { privateJwk, publicJwk, createdAt: new Date().toISOString() } },
      () => resolve()
    );
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

export async function ensureKeypairAndRegister(serverBase, token, userId) {
  if (!userId) throw new Error("ensureKeypairAndRegister: missing userId");

  const { publicKey } = await getOrCreateRsaKeypair(userId);
  const publicKeySpkiB64 = await exportPublicSpkiB64(publicKey);

  async function tryRegister(path) {
    const deviceId = await getDeviceId();
   console.log("DEVICE ID:", deviceId);
    const res = await fetch(`${serverBase}${path}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "x-qm-device-id": deviceId 
      },
      body: JSON.stringify({
        device_id: deviceId,
        pub_jwk: { publicKeySpkiB64 },
        label: "Chrome Extension",
        device_type: "desktop"
      })
    });

    const raw = await res.text().catch(() => "");
    let data = {};
    try {
      data = (res.headers.get("content-type") || "").includes("application/json")
        ? JSON.parse(raw || "{}")
        : { raw };
    } catch {
      data = { raw };
    }

    return { res, data };
  }

  let out = await tryRegister("/org/register-key");
  if (out.res.ok) return;

  out = await tryRegister("/pubkey_register");
  if (out.res.ok) return;

  throw new Error(out.data?.error || out.data?.message || `pubkey_register failed (${out.res.status})`);
}

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
