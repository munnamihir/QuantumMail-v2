/* =========================
   GLOBAL STATE
========================= */
const VaultState = {
  devices: [],
  currentDeviceId: null,
  currentRequestId: null
};

/* =========================
   HELPERS
========================= */
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
   SAFE DEVICE ID (FIXED)
========================= */
async function getDeviceId() {
  return new Promise((resolve) => {
    let done = false;

    function finish(id) {
      if (done) return;
      done = true;

      if (id) {
        localStorage.setItem("qm_device_id", id); // 🔥 persist
      }

      resolve(id);
    }

    function handler(event) {
      if (event.data?.type === "QM_DEVICE_ID_RESPONSE") {
        console.log("✅ Extension deviceId:", event.data.deviceId);
        window.removeEventListener("message", handler);
        finish(event.data.deviceId);
      }
    }

    window.addEventListener("message", handler);

    window.postMessage(
      { source: "qm-portal", type: "GET_DEVICE_ID" },
      "*"
    );

    // 🔥 fallback (NO RANDOM GENERATION)
    setTimeout(() => {
      console.warn("⚠️ Extension not responding, using stored deviceId");

      window.removeEventListener("message", handler);

      const stored = localStorage.getItem("qm_device_id");

      if (!stored) {
        console.error("❌ No deviceId found anywhere");
        finish(null);
      } else {
        finish(stored);
      }
    }, 1200);
  });
}

/* =========================
   INIT
========================= */
document.addEventListener("DOMContentLoaded", initVault);

async function initVault() {
  console.log("INIT START");

  VaultState.currentDeviceId = await getDeviceId();

  console.log("🔥 DEVICE ID:", VaultState.currentDeviceId);

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

  if (!VaultState.devices.length) {
    el.innerHTML = `<span style="color:#9aa6d6">No devices</span>`;
    return;
  }

  const d = VaultState.devices.find(
    x => x.device_id === VaultState.currentDeviceId
  );

  if (!d) {
    el.innerHTML = `
      <span style="color:#ff5d5d">
        Device not matched (ID mismatch)
      </span>
    `;
    return;
  }

  el.innerHTML = `
    <b>${d.label || "This Device"}</b><br/>
    ${d.device_id}<br/>
    <span style="color:#2bd576">${d.status.toUpperCase()}</span>
  `;
}

/* =========================
   DEVICES LIST
========================= */
function renderDevices() {
  const el = $("devicesList");
  el.innerHTML = "";

  if (!VaultState.devices.length) {
    el.innerHTML = `<span style="color:#9aa6d6">No devices found</span>`;
    return;
  }

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
          ? `<button data-trust="${d.device_id}" class="primary">
              🔐 Trust this device
            </button>`
          : ""
      }

      ${
        d.status === "active"
          ? `<button data-revoke="${d.device_id}" class="danger">
              ❌ Revoke
            </button>`
          : ""
      }
    `;

    el.appendChild(div);
  });

  bindDeviceActions();
}

/* =========================
   ACTIONS
========================= */
function bindDeviceActions() {
  const token = getToken();

  /* TRUST */
  document.querySelectorAll("[data-trust]").forEach(btn => {
    btn.onclick = async () => {
      const nickname = prompt("Enter device name:");

      await fetch("/api/devices/trust", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          device_id: btn.dataset.trust,
          label: nickname
        })
      });

      loadDevices();
    };
  });

  /* REVOKE */
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
   RECOVERY FLOW
========================= */
function setStatus(text) {
  const el = $("recoveryStatusText");
  if (el) el.textContent = text;
}

$("startRecoveryBtn").onclick = async () => {
  setStatus("Starting recovery...");

  const res = await fetch("/api/recovery/start", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${getToken()}`,
      "x-qm-device-id": VaultState.currentDeviceId
    }
  });

  const data = await res.json();

  console.log("START RESPONSE:", data);

  VaultState.currentRequestId = data.request_id;

  setStatus("Waiting for approvals...");
};

$("checkRecoveryBtn").onclick = async () => {
  const res = await fetch("/api/recovery/pending", {
    headers: { Authorization: `Bearer ${getToken()}` }
  });

  const data = await res.json();

  const req = data.pending.find(
    r => r.request_id === VaultState.currentRequestId
  );

  if (!req) {
    setStatus("No request found");
    return;
  }

  setStatus(`Approvals: ${req.approvals || 0}`);
};

$("finishRecoveryBtn").onclick = async () => {
  if (!VaultState.currentRequestId) {
    setStatus("Start recovery first ❌");
    return;
  }

  setStatus("Completing recovery...");

  const res = await fetch(
    `/api/recovery/finish/${VaultState.currentRequestId}`,
    {
      headers: { Authorization: `Bearer ${getToken()}` }
    }
  );

  const data = await res.json();

  console.log("FINISH RESPONSE:", data);

  if (!data.vault) {
    setStatus("Quorum not reached ❌");
    return;
  }

  /* 🔑 RESTORE KEY */
  sendToExtension("restore_key", data.vault);

  setStatus("Recovery complete 🎉");
};
