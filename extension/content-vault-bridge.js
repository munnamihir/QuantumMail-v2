// extension/content-vault-bridge.js

(() => {
  console.log("QM Vault Bridge ✅");

  function sendToBackground(type, payload = {}) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type, payload }, resolve);
    });
  }

  function reply(type, payload = {}) {
    window.postMessage({ source: "qm-ext", type, payload }, "*");
  }

  window.addEventListener("message", async (event) => {
    if (event.data?.type === "GET_DEVICE_ID") {
      const { deviceId } = await chrome.storage.local.get("deviceId");
  
      window.postMessage({
        type: "QM_DEVICE_ID_RESPONSE",
        deviceId
      }, "*");
    }
  });

  
  window.addEventListener("message", async (event) => {
    const msg = event.data;
    if (!msg || msg.source !== "qm-portal") return;

    console.log("📩 Bridge received:", msg.type);

    try {
      const res = await sendToBackground(msg.type, msg.payload);

      if (!res?.ok) {
        throw new Error(res?.error || "Action failed");
      }

      /* Map responses back to UI */
      if (msg.type === "load_devices") {
        reply("devices_loaded", res.payload);
      }

      if (msg.type === "trust_this_device") {
        reply("device_trusted", {});
      }

      if (msg.type === "revoke_device") {
        reply("device_revoked", {});
      }

      if (msg.type === "start_recovery") {
        reply("recovery_started", res.payload);
      }

      if (msg.type === "load_pending") {
        reply("pending_loaded", res.payload);
      }

      if (msg.type === "approve_recovery") {
        reply("recovery_approved", {});
      }

      if (msg.type === "finish_recovery") {
        reply("vault_recovered", {});
      }

    } catch (e) {
      console.error("❌ Bridge error:", e);
      reply("vault_error", { error: e.message });
    }
  });
})();
