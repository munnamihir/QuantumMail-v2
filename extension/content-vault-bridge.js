// extension/content-vault-bridge.js
(async () => {
  console.log("QM vault bridge injected ✅", chrome?.runtime?.id);

  function reply(type, payload) {
    window.postMessage({ source: "qm-ext", type, payload }, "*");
  }

  async function getApiBase() {
    const sync = await chrome.storage.sync.get(["serverBase"]);
    const serverBase = (sync.serverBase || "").trim();
    if (serverBase) return serverBase.replace(/\/+$/, "");

    const local = await chrome.storage.local.get(["qm_api_base"]);
    const apiBase = (local.qm_api_base || "").trim();
    if (apiBase) return apiBase.replace(/\/+$/, "");

    throw new Error("Missing API base. Login first so session.serverBase is set.");
  }

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

      if (msg.type === "trust_this_device") {
        const res = await sendToBackground("trust_this_device", msg.payload);

        if (!res?.ok) throw new Error(res?.error || "Trust failed");

        reply("device_trusted", {});
        return;
      }

      if (msg.type === "load_devices") {
        const devices = await qmVault.listTrustedDevices(apiBase);
        reply("devices_loaded", { devices });
        return;
      }

      if (msg.type === "revoke_device") {
        await qmVault.revokeTrustedDevice(apiBase, msg.payload?.device_id);
        reply("device_revoked", { device_id: msg.payload?.device_id });
        return;
      }

      if (msg.type === "start_recovery") {
        const out = await qmVault.startRecoveryRequest(apiBase, msg.payload?.token);
        reply("recovery_started", out);
        return;
      }

      if (msg.type === "load_pending") {
        const pending = await qmVault.getPendingRecovery(apiBase);
        reply("pending_loaded", { pending });
        return;
      }

      if (msg.type === "approve_recovery") {
        await qmVault.approveRecoveryRequest(
          apiBase,
          msg.payload?.request_id,
          msg.payload?.nonce_b64
        );
        reply("recovery_approved", { request_id: msg.payload?.request_id });
        return;
      }

      if (msg.type === "finish_recovery") {
        await qmVault.finishRecoveryFetch(
          apiBase,
          msg.payload?.request_id,
          msg.payload?.token_id,
          msg.payload?.token_secret,
          msg.payload?.token_prefix || "qm-rrt-3"
        );
        reply("vault_recovered", {});
        return;
      }
    } catch (e) {
      reply("vault_error", { error: String(e?.message || e) });
    }
  });
})();
