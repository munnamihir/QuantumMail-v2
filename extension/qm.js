// extension/qm.js

export const DEFAULTS = {
  serverBase: "",
  token: "",
  user: null
};

/* =========================
   DEVICE ID
========================= */
export async function getDeviceId() {
  const { deviceId } = await chrome.storage.local.get("deviceId");

  if (deviceId) return deviceId;

  const newId = "d_" + crypto.randomUUID().replace(/-/g, "");
  await chrome.storage.local.set({ deviceId: newId });

  console.log("NEW DEVICE ID:", newId);
  return newId;
}

/* =========================
   SESSION
========================= */
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

/*================
      apiJson
  ================*/
export async function apiJson(serverBase, path, { method = "GET", token = "", body = null } = {}) {
  const url = serverBase.replace(/\/+$/, "") + path;

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

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(data?.error || `HTTP ${res.status}`);
  }

  return data;
}


/* =========================
   DEVICE REGISTER (PENDING ONLY)
========================= */
export async function ensureDeviceRegistered(serverBase, token, userId) {
  const deviceId = await getDeviceId();
  const { publicKey } = await getOrCreateRsaKeypair(userId);
  const pub_jwk = await crypto.subtle.exportKey("jwk", publicKey);

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
      label: "Chrome Extension",
      device_type: "desktop",
      pub_jwk
    })
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    console.error("REGISTER FAILED:", data);
    throw new Error("Device registration failed");
  }

  return data;
}

/* =========================
   RSA KEYPAIR
========================= */
function keyName(userId) {
  return `qm_rsa_${userId}`;
}

export async function getOrCreateRsaKeypair(userId) {
  const key = keyName(userId);

  const stored = await chrome.storage.local.get(key);
  if (stored[key]) {
    const { privateJwk, publicJwk } = stored[key];

    return {
      privateKey: await crypto.subtle.importKey("jwk", privateJwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]),
      publicKey: await crypto.subtle.importKey("jwk", publicJwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"])
    };
  }

  const kp = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"]
  );

  const privateJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const publicJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);

  await chrome.storage.local.set({
    [key]: { privateJwk, publicJwk }
  });

  return kp;
}

/* =========================
   AES
========================= */
export async function aesEncrypt(text, aad = "gmail") {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) },
    key,
    new TextEncoder().encode(text)
  );

  const raw = await crypto.subtle.exportKey("raw", key);

  return {
    ivB64Url: b64(iv),
    ctB64Url: b64(new Uint8Array(ct)),
    rawDek: new Uint8Array(raw)
  };
}

export async function aesDecrypt(iv, ct, aad, rawKey) {
  const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);

  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(iv), additionalData: new TextEncoder().encode(aad) },
    key,
    fromB64(ct)
  );

  return new TextDecoder().decode(pt);
}

/* =========================
   RSA WRAP
========================= */
export async function rsaWrapDek(pub, raw) {
  const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, raw);
  return b64(new Uint8Array(wrapped));
}

/* =========================
   BASE64
========================= */
function b64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function fromB64(s) {
  const bin = atob(s);
  return new Uint8Array([...bin].map(c => c.charCodeAt(0)));
}
