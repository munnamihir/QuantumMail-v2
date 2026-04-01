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

  window.addEventListener("message", (event) => {
    if (event.data?.type === "GET_DEVICE_ID") {
      console.log("📩 Bridge received: GET_DEVICE_ID");
  
      try {
        chrome.storage.local.get("deviceId", (result) => {
          const deviceId = result.deviceId;
  
          if (!deviceId) {
            console.error("❌ No deviceId in storage");
  
            window.postMessage({
              type: "QM_DEVICE_ID_RESPONSE",
              error: "NO_DEVICE_ID"
            }, "*");
  
            return;
          }
  
          window.postMessage({
            type: "QM_DEVICE_ID_RESPONSE",
            deviceId
          }, "*");
        });
      } catch (err) {
        console.error("❌ Bridge error:", err);
  
        window.postMessage({
          type: "QM_DEVICE_ID_RESPONSE",
          error: "BRIDGE_FAILED"
        }, "*");
      }
    }
    if (msg?.type === "rewrap_message") {
      const { messageId, payload } = msg.payload || {};

      console.log("🔁 Rewrapping message:", messageId);

      chrome.runtime.sendMessage({
        type: "QM_REWRAP_MESSAGE",
        messageId,
        payload
      });

      return; // 🔥 prevent fall-through
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
