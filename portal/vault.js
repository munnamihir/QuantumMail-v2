// portal/vault.js

function $(id) {
  return document.getElementById(id);
}

/* =========================
   Messaging to extension
========================= */
function sendToExtension(type, payload = {}) {
  window.postMessage({ source: "qm-portal", type, payload }, "*");
}

/* =========================
   INIT
========================= */
document.addEventListener("DOMContentLoaded", () => {
  loadDevices();
});

/* =========================
   LOAD DEVICES (via extension)
========================= */
function loadDevices() {
  sendToExtension("load_devices");
}

/* =========================
   RENDER DEVICES
========================= */
function renderDevices(devices) {
  const el = $("devicesList");
  el.innerHTML = "";

  if (!devices.length) {
    el.innerHTML = `<div class="muted">No devices found.</div>`;
    return;
  }

  devices.forEach(d => {
    const status = d.revoked
      ? "revoked"
      : (d.status || "pending");

    const div = document.createElement("div");

    div.innerHTML = `
      <div style="border:1px solid #444; padding:12px; margin:10px; border-radius:8px;">
        <b>${d.label || "Device"}</b><br/>
        ID: ${d.device_id}<br/>
        Type: ${d.device_type}<br/>
        Status: <b>${status}</b>
      </div>
    `;

    el.appendChild(div);
  });
}

/* =========================
   LISTEN FROM EXTENSION
========================= */
window.addEventListener("message", (event) => {
  const msg = event.data;
  if (!msg || msg.source !== "qm-ext") return;

  if (msg.type === "devices_loaded") {
    console.log("DEVICES:", msg.payload.devices);
    renderDevices(msg.payload.devices || []);
  }

  if (msg.type === "device_trusted") {
    $("trustMsg").textContent = "Device trusted successfully.";
    loadDevices();
  }

  if (msg.type === "device_revoked") {
    $("trustMsg").textContent = "Device revoked.";
    loadDevices();
  }

  if (msg.type === "vault_error") {
    const err = msg.payload.error || "Unknown error";
    $("trustErr").textContent = err;
  }
});

/* =========================
   ACTIONS
========================= */

$("trustBtn").onclick = () => {
  sendToExtension("trust_this_device", {
    label: $("deviceLabel").value.trim(),
    device_type: $("deviceType").value
  });
};

$("refreshDevicesBtn").onclick = () => {
  loadDevices();
};
