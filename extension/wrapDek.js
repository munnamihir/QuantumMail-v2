// extension/wrapDek.js
import { ensureWrapKey } from "./qmVault.js";

function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}
function unb64(s) {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

async function importAesKey(raw32) {
  return crypto.subtle.importKey("raw", raw32, { name: "AES-GCM" }, false, ["encrypt","decrypt"]);
}

export async function wrapDek(dekBytes32) {
  const wk = await ensureWrapKey();
  const wkKey = await importAesKey(wk);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wkKey, dekBytes32);

  return { wrapped_dek_b64: b64(new Uint8Array(ct)), wrapped_iv_b64: b64(iv) };
}

export async function unwrapDek(wrapped_dek_b64, wrapped_iv_b64) {
  const wk = await ensureWrapKey();
  const wkKey = await importAesKey(wk);

  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(wrapped_iv_b64) },
    wkKey,
    unb64(wrapped_dek_b64)
  );
  return new Uint8Array(pt); // 32 bytes
}
