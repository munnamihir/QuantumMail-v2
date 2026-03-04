// extension/content-vault-bridge.js
// Classic content script (no top-level imports).
// We dynamically import module code using chrome.runtime.getURL().

(async () => {
  function reply(type, payload) {
    window.postMessage({ source: "qm-ext", type, payload }, "*");
  }

  async function getApiBase() {
    const { qm_api_base } = await chrome.storage.local.get(["qm_api_base"]);
    if (!qm_api_base) throw new Error("Missing qm_api_base in extension storage. Set API base / login once.");
    return qm_api_base;
  }

  // Load module helpers dynamically
  const qmVaultUrl = chrome.runtime.getURL("extension/qmVault.js");
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
