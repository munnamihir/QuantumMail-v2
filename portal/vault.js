function $(id) {
  return document.getElementById(id);
}

function sendToExtension(type, payload = {}) {
  window.postMessage({ source: "qm-portal", type, payload }, "*");
}

/* INIT */
document.addEventListener("DOMContentLoaded", () => {
  loadDevices();
});

/* LOAD DEVICES */
function loadDevices() {
  sendToExtension("load_devices");
}

/* RENDER */
function renderDevices(devices) {
  const el = $("devicesList");
  el.innerHTML = "";

  if (!devices.length) {
    el.innerHTML = `<div>No devices found</div>`;
    return;
  }

  devices.forEach(d => {
    const div = document.createElement("div");

    div.innerHTML = `
      <div style="border:1px solid #444; padding:10px; margin:10px;">
        <b>${d.label || "Device"}</b><br/>
        ID: ${d.device_id}<br/>
        Type: ${d.device_type}<br/>
        Status: ${d.status}
      </div>
    `;

    el.appendChild(div);
  });
}

/* LISTENER */
window.addEventListener("message", (event) => {
  const msg = event.data;
  if (!msg || msg.source !== "qm-ext") return;

  if (msg.type === "devices_loaded") {
    renderDevices(msg.payload.devices || []);
  }

  if (msg.type === "device_trusted") {
    $("trustMsg").textContent = "Device trusted!";
    loadDevices();
  }

  if (msg.type === "vault_error") {
    $("trustErr").textContent = msg.payload.error;
  }
});

/* ACTIONS */
$("trustBtn").onclick = () => {
  sendToExtension("trust_this_device", {
    label: $("deviceLabel").value.trim(),
    device_type: $("deviceType").value
  });
};

$("refreshDevicesBtn").onclick = () => {
  loadDevices();
};
