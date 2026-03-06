// extension/qmVault.js
import { apiJson, getSession } from "./qm.js";

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
  const salt = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode("qm-recovery|" + tokenId)
  );

  const baseKey = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: new TextEncoder().encode("qm-vault-wrap-v3")
    },
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

async function ensureLocalDeviceIdentity() {
  const existing = await getLocal("qm_device_id");
  const priv = await getLocal("qm_device_priv_jwk");
  const pub = await getLocal("qm_device_pub_jwk");

  if (existing && priv && pub) {
    return { device_id: existing, priv_jwk: priv, pub_jwk: pub };
  }

  const device_id = randId("d_");
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const priv_jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pub_jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);

  await setLocal({
    qm_device_id: device_id,
    qm_device_priv_jwk: priv_jwk,
    qm_device_pub_jwk: pub_jwk
  });

  return { device_id, priv_jwk, pub_jwk };
}

export async function trustCurrentDevice(apiBase, label = "", deviceType = "desktop") {
  const ident = await ensureLocalDeviceIdentity();
  const session = await getSession();

  const defaultLabel =
    label ||
    (session?.user?.username ? `${session.user.username} device` : navigator.userAgent.slice(0, 48));

  const out = await apiJson(apiBase, "/api/devices/register", {
    method: "POST",
    body: {
      device_id: ident.device_id,
      label: defaultLabel,
      device_type: deviceType,
      pub_jwk: ident.pub_jwk
    }
  });

  return out.device;
}

export async function listTrustedDevices(apiBase) {
  const out = await apiJson(apiBase, "/api/devices/list", { method: "GET" });
  return out.devices || [];
}

export async function revokeTrustedDevice(apiBase, deviceId) {
  await apiJson(apiBase, "/api/devices/revoke", {
    method: "POST",
    body: { device_id: deviceId }
  });
  return true;
}

export async function ensureWrapKey() {
  const wkB64 = await getLocal("qm_wk_b64");
  if (wkB64) return unb64(wkB64);

  const wk = crypto.getRandomValues(new Uint8Array(32));
  await setLocal({ qm_wk_b64: b64(wk) });
  return wk;
}

async function getUserId() {
  const session = await getSession();
  const userId = session?.user?.userId || session?.userId || session?.user?.id || "";
  if (!userId) throw new Error("Missing userId in session.");
  return userId;
}

async function getStoredRsaBundle() {
  const userId = await getUserId();
  const key = `qm_rsa_${userId}`;
  const bundle = await getLocal(key);
  if (!bundle?.privateJwk || !bundle?.publicJwk) {
    throw new Error("RSA keypair not found locally. Generate/login first on the original device.");
  }
  return { key, bundle };
}

export async function setupRecoveryVault(apiBase) {
  const init = await apiJson(apiBase, "/api/recovery/init", { method: "POST", body: {} });
  const token_id = init.token_id;

  const secretBytes = crypto.getRandomValues(new Uint8Array(32));
  const token_secret = b64(secretBytes).replace(/=+$/, "");

  const wk = await ensureWrapKey();
  const { key: rsaStorageKey, bundle: rsaBundle } = await getStoredRsaBundle();

  const vaultPayload = {
    version: 3,
    wk_b64: b64(wk),
    rsa_storage_key: rsaStorageKey,
    rsa_bundle: rsaBundle
  };

  const key = await hkdfKeyFromToken(token_id, token_secret);
  const vaultBytes = new TextEncoder().encode(JSON.stringify(vaultPayload));
  const { iv, ct } = await aesGcmEncrypt(key, vaultBytes);

  const token_verifier_hash = await sha256Hex("qm|v3|" + token_id + "|" + token_secret);

  await apiJson(apiBase, "/api/recovery/vault", {
    method: "PUT",
    body: {
      token_id,
      token_verifier_hash,
      enc_wk_b64: b64(ct),   // keeping same server field name; now contains whole vault blob
      iv_b64: b64(iv),
      wk_version: 3
    }
  });

  await setLocal({
    qm_token_id: token_id,
    qm_token_verifier_hash: token_verifier_hash
  });

  return {
    token_id,
    token_secret,
    display: `qm-rrt-3|${token_id}|${token_secret}`
  };
}

export async function startRecoveryRequest(apiBase, tokenString) {
  const parts = String(tokenString || "").split("|");
  if (parts.length !== 3 || (parts[0] !== "qm-rrt-2" && parts[0] !== "qm-rrt-3")) {
    throw new Error("Bad token format. Expected: qm-rrt-3|token_id|token_secret");
  }

  const token_id = parts[1];
  const token_secret = parts[2];

  const ident = await ensureLocalDeviceIdentity();
  const token_verifier_hash = await sha256Hex(
    `${parts[0] === "qm-rrt-3" ? "qm|v3|" : "qm|v2|"}${token_id}|${token_secret}`
  );

  const out = await apiJson(apiBase, "/api/recovery/quorum/start", {
    method: "POST",
    body: {
      token_id,
      token_verifier_hash,
      requester_device_id: ident.device_id
    }
  });

  return {
    request_id: out.request_id,
    nonce_b64: out.nonce_b64,
    token_id,
    token_secret,
    token_prefix: parts[0]
  };
}

export async function getPendingRecovery(apiBase) {
  const out = await apiJson(apiBase, "/api/recovery/quorum/pending", { method: "GET" });
  return out.requests || [];
}

async function signWithDevice(priv_jwk, msg) {
  const priv = await crypto.subtle.importKey("jwk", priv_jwk, { name: "Ed25519" }, false, ["sign"]);
  const msgBytes = new TextEncoder().encode(msg);
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, priv, msgBytes);
  return b64(new Uint8Array(sig));
}

export async function approveRecoveryRequest(apiBase, request_id, nonce_b64) {
  const ident = await ensureLocalDeviceIdentity();
  const msg = `qm-recover-v1|${request_id}|${nonce_b64}`;
  const sig_b64 = await signWithDevice(ident.priv_jwk, msg);

  await apiJson(apiBase, "/api/recovery/quorum/approve", {
    method: "POST",
    body: {
      request_id,
      device_id: ident.device_id,
      sig_b64
    }
  });

  return true;
}

export async function finishRecoveryFetch(apiBase, request_id, token_id, token_secret, tokenPrefix = "qm-rrt-3") {
  const verifierPrefix = tokenPrefix === "qm-rrt-2" ? "qm|v2|" : "qm|v3|";
  const token_verifier_hash = await sha256Hex(`${verifierPrefix}${token_id}|${token_secret}`);

  const out = await apiJson(apiBase, "/api/recovery/quorum/fetch", {
    method: "POST",
    body: {
      request_id,
      token_id,
      token_verifier_hash
    }
  });

  const v = out.vault;
  const key = await hkdfKeyFromToken(v.token_id, token_secret);
  const vaultBytes = await aesGcmDecrypt(key, unb64(v.iv_b64), unb64(v.enc_wk_b64));

  let vault;
  try {
    vault = JSON.parse(new TextDecoder().decode(vaultBytes));
  } catch {
    throw new Error("Recovered vault payload is invalid.");
  }

  if (!vault?.wk_b64 || !vault?.rsa_storage_key || !vault?.rsa_bundle) {
    throw new Error("Recovered vault is missing WK or RSA bundle.");
  }

  await setLocal({
    qm_wk_b64: vault.wk_b64,
    [vault.rsa_storage_key]: vault.rsa_bundle
  });

  return true;
}
