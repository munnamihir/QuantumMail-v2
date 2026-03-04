// extension/content-vault-bridge.js
// Classic content script (no top-level imports).
// We dynamically import module code using chrome.runtime.getURL().
console.log("QM vault bridge injected ✅", chrome?.runtime?.id);
(async () => {
  function reply(type, payload) {
    window.postMessage({ source: "qm-ext", type, payload }, "*");
  }

  async function getApiBase() {
  // 1) Prefer your existing session in chrome.storage.sync (serverBase)
  const sync = await chrome.storage.sync.get(["serverBase"]);
  const serverBase = (sync.serverBase || "").trim();
  if (serverBase) return serverBase.replace(/\/+$/, "");

  // 2) Fallback: legacy/local key if you ever set it
  const local = await chrome.storage.local.get(["qm_api_base"]);
  const apiBase = (local.qm_api_base || "").trim();
  if (apiBase) return apiBase.replace(/\/+$/, "");

  throw new Error("Missing API base. Set session.serverBase (sync) by logging in, or set qm_api_base (local).");
}

  // Load module helpers dynamically
  const qmVaultUrl = chrome.runtime.getURL("qmVault.js");
  const qmVault = await import(qmVaultUrl);

  window.addEventListener("message", async (event) => {
    const msg = event.data;
    if (!msg || msg.source !== "qm-portal") return;

    try {
      const apiBase = await getApiBase();

      if (msg.type === "enable_vault") {
        const out = await qmVault.setupRecoveryVault(apiBase);
        reply("vault_enabled", { token_display: out.display });
        return;
      }

      if (msg.type === "start_recovery") {
        const { token } = msg.payload || {};
        const out = await qmVault.startRecoveryRequest(apiBase, token);
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
        await qmVault.approveRecoveryRequest(apiBase, request_id, nonce_b64);
        reply("recovery_approved", { request_id });
        return;
      }

      if (msg.type === "finish_recovery") {
        const { request_id, token_id, token_secret } = msg.payload || {};
        await qmVault.finishRecoveryFetch(apiBase, request_id, token_id, token_secret);
        reply("vault_recovered", {});
        return;
      }
    } catch (e) {
      reply("vault_error", { error: String(e?.message || e) });
    }
  });

  // Optional: confirm loaded
  // console.log("QM vault bridge loaded");
})();
