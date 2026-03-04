// extension/content-vault-bridge.js
import {
  setupRecoveryVault,
  startRecoveryRequest,
  approveRecoveryRequest,
  finishRecoveryFetch
} from "./qmVault.js";

async function getLocal(key) {
  return new Promise((resolve) => chrome.storage.local.get([key], (r) => resolve(r[key] ?? null)));
}

// Your extension already stores API base somewhere (you used this pattern across the repo).
// If you store it under a different key, change it here.
async function getApiBase() {
  const apiBase = await getLocal("qm_api_base");
  if (!apiBase) throw new Error("Missing qm_api_base in extension storage. Log in once first.");
  return apiBase;
}

function reply(type, payload) {
  window.postMessage({ source: "qm-ext", type, payload }, "*");
}

window.addEventListener("message", async (event) => {
  const msg = event.data;
  if (!msg || msg.source !== "qm-portal") return;

  try {
    const apiBase = await getApiBase();

    if (msg.type === "enable_vault") {
      const out = await setupRecoveryVault(apiBase);
      reply("vault_enabled", { token_display: out.display });
      return;
    }

    if (msg.type === "start_recovery") {
      const { token } = msg.payload || {};
      const out = await startRecoveryRequest(apiBase, token);
      reply("recovery_started", {
        request_id: out.request_id,
        nonce_b64: out.nonce_b64,
        token_id: out.token_id,
        token_secret: out.token_secret
      });
      return;
    }

    if (msg.type === "approve_recovery") {
      const { request_id, nonce_b64 } = msg.payload || {};
      await approveRecoveryRequest(apiBase, request_id, nonce_b64);
      reply("recovery_approved", { request_id });
      return;
    }

    if (msg.type === "finish_recovery") {
      const { request_id, token_id, token_secret } = msg.payload || {};
      await finishRecoveryFetch(apiBase, request_id, token_id, token_secret);
      reply("vault_recovered", {});
      return;
    }
  } catch (e) {
    reply("vault_error", { error: String(e?.message || e) });
  }
});
