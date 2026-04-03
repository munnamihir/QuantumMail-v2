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
    const msg = event.data;

    /* =========================
       GET DEVICE ID
    ========================= */
    if (msg?.type === "GET_DEVICE_ID") {
      console.log("📩 Bridge received: GET_DEVICE_ID");

      chrome.storage.local.get("deviceId", (result) => {
        const deviceId = result.deviceId;

        if (!deviceId) {
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

      return;
    }

    /* =========================
       REWRAP MESSAGE (FIXED)
    ========================= */
    if (msg.type === "QM_REWRAP_MESSAGE" || msg.type === "rewrap_message") {
      const messageId = msg.payload?.messageId || msg.messageId;
      const payload = msg.payload?.payload || msg.payload;
    
      if (!messageId || !payload) {
        console.warn("⚠️ Invalid rewrap payload:", msg);
        return;
      }
    
      console.log("🔁 Rewrapping message:", messageId);
    
      chrome.runtime.sendMessage(
        {
          type: "QM_REWRAP_MESSAGE",
          messageId,
          payload
        },
        (response) => {
          if (!response?.ok) {
            console.error("❌ Rewrap failed:", response);
          } else {
            console.log("✅ Rewrap success:", messageId);
          }
        }
      );
    }

    /* =========================
       VAULT → EXTENSION FLOW
    ========================= */
    if (!msg || msg.source !== "qm-portal") return;

    if (msg.type === "QM_REWRAP_MESSAGE" || msg.type === "rewrap_message") {
      return; // already handled above
    }
    console.log("📩 Bridge received:", msg.type);

    try {
      const res = await sendToBackground(msg.type, msg.payload);

      if (!res?.ok && !res?.skipped) {
        throw new Error(res?.error || "Action failed");
      }

      switch (msg.type) {
        case "load_devices":
          reply("devices_loaded", res.payload);
          break;

        case "trust_this_device":
          reply("device_trusted", {});
          break;

        case "revoke_device":
          reply("device_revoked", {});
          break;

        case "start_recovery":
          reply("recovery_started", res.payload);
          break;

        case "load_pending":
          reply("pending_loaded", res.payload);
          break;

        case "approve_recovery":
          reply("recovery_approved", {});
          break;

        case "finish_recovery":
          reply("vault_recovered", {});
          break;
        
        case "QM_RESTORE_KEY":
          reply("vault_recovered", {});
          break;

        default:
          console.warn("Unknown message:", msg.type);
      }

    } catch (e) {
      console.error("❌ Bridge error:", e);
      reply("vault_error", { error: e.message });
    }
  });

})();
