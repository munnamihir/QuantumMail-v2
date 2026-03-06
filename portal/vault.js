// portal/vault.js
function $(id) {
  return document.getElementById(id);
}

function sendToExtension(type, payload = {}) {
  window.postMessage({ source: "qm-portal", type, payload }, "*");
}

let lastRecovery = null;

function clearMsgs() {
  ["trustMsg","trustErr","vaultMsg","vaultErr","recoverMsg","recoverErr","approveMsg","approveErr"]
    .forEach((id) => { if ($(id)) $(id).textContent = ""; });
}

function renderDevices(devices) {
  const wrap = $("devicesList");
  wrap.innerHTML = "";

  if (!devices?.length) {
    wrap.innerHTML = `<div class="muted">No trusted devices yet.</div>`;
    return;
  }

  devices.forEach((d) => {
    const el = document.createElement("div");
    el.className = "item";
    el.innerHTML = `
      <div>
        <div class="itemTitle">${d.label || d.device_id}</div>
        <div class="muted">${d.device_type || "device"} · ${d.revoked ? "Revoked" : "Trusted"}</div>
      </div>
      <div class="itemActions">
        ${d.revoked ? "" : `<button class="danger" data-revoke="${d.device_id}">Revoke</button>`}
      </div>
    `;
    wrap.appendChild(el);
  });

  wrap.querySelectorAll("[data-revoke]").forEach((btn) => {
    btn.onclick = () => {
      clearMsgs();
      sendToExtension("revoke_device", { device_id: btn.dataset.revoke });
    };
  });
}

function renderPending(items) {
  const wrap = $("pendingList");
  wrap.innerHTML = "";

  if (!items?.length) {
    wrap.innerHTML = `<div class="muted">No pending recovery requests.</div>`;
    return;
  }

  items.forEach((r) => {
    const el = document.createElement("div");
    el.className = "item";
    el.innerHTML = `
      <div>
        <div class="itemTitle">${r.request_id}</div>
        <div class="muted">Requester: ${r.requester_device_id}</div>
      </div>
      <div class="itemActions">
        <button class="primary" data-approve="${r.request_id}" data-nonce="${r.nonce_b64}">Approve</button>
      </div>
    `;
    wrap.appendChild(el);
  });

  wrap.querySelectorAll("[data-approve]").forEach((btn) => {
    btn.onclick = () => {
      clearMsgs();
      sendToExtension("approve_recovery", {
        request_id: btn.dataset.approve,
        nonce_b64: btn.dataset.nonce
      });
    };
  });
}

window.addEventListener("message", (event) => {
  const msg = event.data;
  if (!msg || msg.source !== "qm-ext") return;

  if (msg.type === "device_trusted") {
    $("trustMsg").textContent = "Device trusted successfully.";
    sendToExtension("load_devices");
    return;
  }

  if (msg.type === "devices_loaded") {
    renderDevices(msg.payload.devices || []);
    return;
  }

  if (msg.type === "device_revoked") {
    $("trustMsg").textContent = "Device revoked.";
    sendToExtension("load_devices");
    return;
  }

  if (msg.type === "vault_enabled") {
    $("tokenOut").textContent = msg.payload.token_display;
    $("vaultMsg").textContent = "Vault enabled. Save the token now.";
    return;
  }

  if (msg.type === "recovery_started") {
    lastRecovery = msg.payload;
    $("reqOut").textContent = JSON.stringify({
      request_id: lastRecovery.request_id,
      nonce_b64: lastRecovery.nonce_b64
    }, null, 2);
    $("finishBtn").disabled = false;
    $("recoverMsg").textContent = "Recovery request started. Approve it on one trusted device.";
    return;
  }

  if (msg.type === "pending_loaded") {
    renderPending(msg.payload.pending || []);
    return;
  }

  if (msg.type === "recovery_approved") {
    $("approveMsg").textContent = "Recovery approved. Go back to the new device and click Finish Recovery.";
    return;
  }

  if (msg.type === "vault_recovered") {
    $("recoverMsg").textContent = "Recovery successful. RSA + vault keys restored on this device.";
    return;
  }

  if (msg.type === "vault_error") {
    const err = msg.payload.error || "Unknown error";
    $("trustErr").textContent = err;
    $("vaultErr").textContent = err;
    $("recoverErr").textContent = err;
    $("approveErr").textContent = err;
    return;
  }
});

$("trustBtn").onclick = () => {
  clearMsgs();
  sendToExtension("trust_this_device", {
    label: $("deviceLabel").value.trim(),
    device_type: $("deviceType").value
  });
};

$("refreshDevicesBtn").onclick = () => {
  clearMsgs();
  sendToExtension("load_devices");
};

$("enableBtn").onclick = () => {
  clearMsgs();
  sendToExtension("enable_vault");
};

$("startBtn").onclick = () => {
  clearMsgs();
  const token = $("tokenIn").value.trim();
  if (!token) {
    $("recoverErr").textContent = "Paste your recovery token first.";
    return;
  }
  sendToExtension("start_recovery", { token });
};

$("finishBtn").onclick = () => {
  clearMsgs();
  if (!lastRecovery) {
    $("recoverErr").textContent = "Start recovery first.";
    return;
  }
  sendToExtension("finish_recovery", {
    request_id: lastRecovery.request_id,
    token_id: lastRecovery.token_id,
    token_secret: lastRecovery.token_secret,
    token_prefix: lastRecovery.token_prefix || "qm-rrt-3"
  });
};

$("loadPendingBtn").onclick = () => {
  clearMsgs();
  sendToExtension("load_pending");
};

sendToExtension("load_devices");
