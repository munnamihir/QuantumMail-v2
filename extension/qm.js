// extension/qm.js

/* =========================
   DEVICE ID (STABLE)
========================= */
export async function getOrCreateDeviceId() {
  const stored = await chrome.storage.local.get("qm_device_id");

  if (stored.qm_device_id) {
    return stored.qm_device_id;
  }

  const deviceId = "dev_" + crypto.randomUUID();

  await chrome.storage.local.set({ qm_device_id: deviceId });

  return deviceId;
}

/* =========================
   KEYPAIR PER DEVICE
========================= */
export async function getOrCreateRsaKeypair(deviceId) {
  const keyName = `qm_rsa_${deviceId}`;

  const stored = await chrome.storage.local.get(keyName);

  if (stored[keyName]) {
    return stored[keyName];
  }

  const keypair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );

  const exported = {
    publicKey: await crypto.subtle.exportKey("spki", keypair.publicKey),
    privateKey: await crypto.subtle.exportKey("jwk", keypair.privateKey)
  };

  await chrome.storage.local.set({
    [keyName]: exported
  });

  return exported;
}

/* =========================
   GET PUBLIC KEY BASE64
========================= */
export async function getPublicKeySpkiB64(deviceId) {
  const keypair = await getOrCreateRsaKeypair(deviceId);

  return btoa(
    String.fromCharCode(...new Uint8Array(keypair.publicKey))
  );
}

/* =========================
   UNWRAP DEK
========================= */
export async function rsaUnwrapDek(deviceId, wrappedDekB64) {
  const keyName = `qm_rsa_${deviceId}`;
  const stored = await chrome.storage.local.get(keyName);

  if (!stored[keyName]) {
    throw new Error("No private key for this device");
  }

  const privateKey = await crypto.subtle.importKey(
    "jwk",
    stored[keyName].privateKey,
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    false,
    ["decrypt"]
  );

  const wrapped = Uint8Array.from(atob(wrappedDekB64), c => c.charCodeAt(0));

  return await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    wrapped
  );
}

/* =========================
   AES DECRYPT
========================= */
export async function aesDecrypt(dek, ivB64, ciphertextB64) {
  const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
  const ciphertext = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));

  const key = await crypto.subtle.importKey(
    "raw",
    dek,
    "AES-GCM",
    false,
    ["decrypt"]
  );

  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );

  return new TextDecoder().decode(plain);
}
