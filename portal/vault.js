function $(id) {
  return document.getElementById(id);
}

function getToken() {
  return localStorage.getItem("qm_token");
}

function getDeviceId() {
  return localStorage.getItem("qm_device_id");
}

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
   LOAD DEVICES
========================= */
async function loadDevices() {
  const token = getToken();

  const res = await fetch("/api/devices/list", {
    headers: { Authorization: `Bearer ${token}` }
  });

  const data = await res.json();

  renderDevices(data.devices || []);
  renderCurrentDevice(data.devices || []);
}

/* =========================
   CURRENT DEVICE
========================= */
function renderCurrentDevice(devices) {
  const el = $("currentDeviceBox");
  const id = getDeviceId();

  const d = devices.find(x => x.device_id === id);

  if (!d) {
    el.innerHTML = "Device not registered";
    return;
  }

  el.innerHTML = `
    <b>${d.label || "This Device"}</b><br/>
    ${d.device_id}<br/>
    <span style="color:#2bd576">ACTIVE</span>
  `;
}

/* =========================
   DEVICES LIST
========================= */
function renderDevices(devices) {
  const el = $("devicesList");
  el.innerHTML = "";

  devices.forEach(d => {
    const div = document.createElement("div");

    div.className = "device";

    div.innerHTML = `
      <b>${d.label || "Device"}</b><br/>
      ${d.device_id}<br/>
      <span>${d.status}</span><br/><br/>

      ${d.status === "active"
        ? `<button data-revoke="${d.device_id}" class="danger">Revoke</button>`
        : ""}

      <button data-approve="${d.device_id}" class="success">Approve Recovery</button>
    `;

    el.appendChild(div);
  });

  /* REVOKE */
  el.querySelectorAll("[data-revoke]").forEach(btn => {
    btn.onclick = async () => {
      const token = getToken();

      await fetch("/org/revoke-device", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ deviceId: btn.dataset.revoke })
      });

      loadDevices();
    };
  });

  /* APPROVE */
  el.querySelectorAll("[data-approve]").forEach(btn => {
    btn.onclick = async () => {
      const token = getToken();

      await fetch("/api/recovery/approve", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          "x-qm-device-id": getDeviceId()
        },
        body: JSON.stringify({
          request_id: window.currentRequestId
        })
      });

      alert("Approved");
    };
  });
}

/* =========================
   RECOVERY FLOW
========================= */

$("startRecoveryBtn").onclick = async () => {
  const res = await fetch("/api/recovery/start", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${getToken()}`,
      "x-qm-device-id": getDeviceId()
    }
  });

  const data = await res.json();

  window.currentRequestId = data.request_id;

  $("recoveryStatus").textContent = "Waiting for approvals...";
};

$("checkRecoveryBtn").onclick = async () => {
  const res = await fetch("/api/recovery/pending", {
    headers: { Authorization: `Bearer ${getToken()}` }
  });

  const data = await res.json();

  const req = data.pending.find(
    r => r.request_id === window.currentRequestId
  );

  $("recoveryStatus").textContent = req?.status || "Not found";
};

$("finishRecoveryBtn").onclick = async () => {
  const res = await fetch(
    `/api/recovery/finish/${window.currentRequestId}`,
    { headers: { Authorization: `Bearer ${getToken()}` } }
  );

  const data = await res.json();

  if (!data.vault) {
    $("recoveryStatus").textContent = "Not ready";
    return;
  }

  sendToExtension("restore_key", data.vault);

  $("recoveryStatus").textContent = "Recovery complete 🎉";
};
