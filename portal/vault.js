const VaultState = {
  devices: [],
  currentDeviceId: null,
  currentRequestId: null
};

function $(id) {
  return document.getElementById(id);
}

function getToken() {
  return localStorage.getItem("qm_token");
}

function sendToExtension(type, payload = {}) {
  window.postMessage({ source: "qm-portal", type, payload }, "*");
}

/* =========================
   FIXED DEVICE ID (NO RANDOM)
========================= */
async function getDeviceId() {
  return new Promise((resolve, reject) => {
    function handler(event) {
      if (event.data?.type === "QM_DEVICE_ID_RESPONSE") {
        window.removeEventListener("message", handler);

        if (event.data.error) {
          reject(event.data.error);
        } else {
          resolve(event.data.deviceId);
        }
      }
    }

    window.addEventListener("message", handler);

    window.postMessage({
      source: "qm-portal",
      type: "GET_DEVICE_ID"
    }, "*");

    setTimeout(() => {
      window.removeEventListener("message", handler);
      reject("Extension not responding");
    }, 1500);
  });
}

/* =========================
   INIT
========================= */
document.addEventListener("DOMContentLoaded", initVault);

async function initVault() {
  console.log("INIT START");

  try {
    VaultState.currentDeviceId = await getDeviceId();
    console.log("DEVICE ID:", VaultState.currentDeviceId);
  } catch (e) {
    console.error("❌ Cannot get deviceId:", e);
    $("devicesList").innerHTML = "Extension required ❌";
    return;
  }

  await loadDevices();
}

/* =========================
   LOAD DEVICES
========================= */
async function loadDevices() {
  try {
    const res = await fetch("/api/devices/list", {
      headers: { Authorization: `Bearer ${getToken()}` }
    });

    const data = await res.json();

    console.log("DEVICES API:", data);

    VaultState.devices = data.devices || [];

    renderDevices();
    renderCurrentDevice();

  } catch (e) {
    console.error("LOAD DEVICES FAILED:", e);
  }
}

/* =========================
   CURRENT DEVICE
========================= */
function renderCurrentDevice() {
  const el = $("currentDeviceBox");

  const d = VaultState.devices.find(
    x => x.device_id === VaultState.currentDeviceId
  );

  if (!d) {
    el.innerHTML = `<span style="color:#ff5d5d">Device mismatch ❌</span>`;
    return;
  }

  el.innerHTML = `
    <b>${d.label || "This Device"}</b><br/>
    ${d.device_id}<br/>
    <span style="color:#2bd576">${d.status}</span>
  `;
}

/* =========================
   DEVICES LIST
========================= */
function renderDevices() {
  const el = $("devicesList");
  el.innerHTML = "";

  VaultState.devices.forEach(d => {
    const isCurrent = d.device_id === VaultState.currentDeviceId;

    const div = document.createElement("div");
    div.className = "device";

    div.innerHTML = `
      <b>${d.label || "Device"}</b><br/>
      ${d.device_id}<br/>
      <span>${d.status}</span><br/><br/>

      ${
        d.status === "pending" && isCurrent
          ? `<button data-trust="${d.device_id}" class="primary">Trust</button>`
          : ""
      }

      ${
        d.status === "active"
          ? `<button data-revoke="${d.device_id}" class="danger">Revoke</button>`
          : ""
      }
    `;

    el.appendChild(div);
  });

  bindActions();
}

function bindActions() {
  const token = getToken();

  document.querySelectorAll("[data-trust]").forEach(btn => {
    btn.onclick = async () => {
      const label = prompt("Device name:");

      await fetch("/api/devices/trust", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          device_id: btn.dataset.trust,
          label
        })
      });

      loadDevices();
    };
  });

  document.querySelectorAll("[data-revoke]").forEach(btn => {
    btn.onclick = async () => {
      await fetch("/api/devices/revoke", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          device_id: btn.dataset.revoke
        })
      });

      loadDevices();
    };
  });
}

/* =========================
   RECOVERY
========================= */
function setStatus(t) {
  const el = $("recoveryStatusText");
  if (el) el.textContent = t;
}

$("startRecoveryBtn").onclick = async () => {
  const res = await fetch("/api/recovery/start", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${getToken()}`,
      "x-qm-device-id": VaultState.currentDeviceId
    }
  });

  const data = await res.json();

  VaultState.currentRequestId = data.request_id;

  setStatus("Waiting approvals...");
};

$("finishRecoveryBtn").onclick = async () => {
  const res = await fetch(
    `/api/recovery/finish/${VaultState.currentRequestId}`,
    {
      headers: { Authorization: `Bearer ${getToken()}` }
    }
  );

  const data = await res.json();

  if (!data.vault) {
    setStatus("Not ready ❌");
    return;
  }

  sendToExtension("restore_key", data.vault);

  setStatus("Recovered 🎉");
};
