const VaultState = {
  devices: [],
  currentDeviceId: null,
  activeRequest: null,
  approvals: 0,
  threshold: 2
};

/* =========================
   HELPERS
========================= */

function renderAll() {
  renderCurrentDevice();
  renderDevices();
  renderRecovery();
}

function startAutoRefresh() {
  setInterval(async () => {
    await syncRecoveryState();
    renderRecovery();
  }, 3000); // every 3 seconds
}

async function syncRecoveryState() {
  const res = await fetch("/api/recovery/pending", {
    headers: { Authorization: `Bearer ${getToken()}` }
  });

  const data = await res.json();

  const req = data.pending?.[0];

  if (!req) {
    VaultState.activeRequest = null;
    VaultState.approvals = 0;
    return;
  }

  VaultState.activeRequest = req;
  VaultState.approvals = req.approvals || 0;
}

function $(id) {
  const el = document.getElementById(id);
  if (!el) console.warn(`⚠️ Element not found: ${id}`);
  return el;
}

function getToken() {
  return localStorage.getItem("qm_token");
}

async function getDeviceId() {
  return new Promise((resolve) => {
    let done = false;

    function finish(id) {
      if (done) return;
      done = true;
      resolve(id);
    }

    // 🔥 listen first (important)
    function handler(event) {
      if (event.data?.type === "QM_DEVICE_ID_RESPONSE") {
        console.log("✅ Got deviceId from extension:", event.data.deviceId);
        window.removeEventListener("message", handler);
        finish(event.data.deviceId);
      }
    }

    window.addEventListener("message", handler);

    // 🔥 send request
    window.postMessage(
      { source: "qm-portal", type: "GET_DEVICE_ID" },
      "*"
    );

    // 🔥 fallback (CRITICAL)
    setTimeout(() => {
      console.warn("⚠️ Extension not responding, using fallback");

      window.removeEventListener("message", handler);

      let id = localStorage.getItem("qm_device_id");

      if (!id) {
        id = crypto.randomUUID();
        localStorage.setItem("qm_device_id", id);
      }

      finish(id);
    }, 1200);
  });
}

function sendToExtension(type, payload = {}) {
  window.postMessage({ source: "qm-portal", type, payload }, "*");
}

function setStep(step) {
  ["step1", "step2", "step3"].forEach((id, i) => {
    const el = document.getElementById(id);
    if (!el) return;

    el.classList.remove("active", "done");

    if (i + 1 < step) el.classList.add("done");
    if (i + 1 === step) el.classList.add("active");
  });
}

function setStatus(text) {
  const el = document.getElementById("recoveryStatusText");
  if (!el) return;
  el.textContent = text;
}

function setApprovals(count) {
  const el = document.getElementById("approvalCount");
  if (!el) return;
  el.textContent = count;
}

function bindDeviceActions() {
  /* TRUST */
  document.querySelectorAll("[data-trust]").forEach(btn => {
    btn.onclick = async () => {
      const label = prompt("Device name:");

      await fetch("/api/devices/trust", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${getToken()}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          device_id: btn.dataset.trust,
          label
        })
      });

      await loadDevices();
      renderAll();
    };
  });

  /* REVOKE */
  document.querySelectorAll("[data-revoke]").forEach(btn => {
    btn.onclick = async () => {
      await fetch("/api/devices/revoke", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${getToken()}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          device_id: btn.dataset.revoke
        })
      });

      await loadDevices();
      renderAll();
    };
  });

  /* APPROVE */
  document.querySelectorAll("[data-approve]").forEach(btn => {
    btn.onclick = async () => {
      await fetch("/api/recovery/approve", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${getToken()}`,
          "Content-Type": "application/json",
          "x-qm-device-id": VaultState.currentDeviceId
        },
        body: JSON.stringify({
          request_id: VaultState.activeRequest.request_id
        })
      });

      setStatus("Approved ✅");
    };
  });
}

/* =========================
   INIT
========================= */

document.addEventListener("DOMContentLoaded", async () => {
  await initVault();
});

async function initVault() {
  setStatus("Loading vault...");

  console.log("INIT START");

  VaultState.currentDeviceId = await getDeviceId();
  
  console.log("DEVICE ID:", VaultState.currentDeviceId);
  
  await loadDevices();
  
  console.log("DEVICES LOADED");
  
  await syncRecoveryState();

  renderAll();

  startAutoRefresh();
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

    /* 🔥 CRITICAL FIX */
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

async function renderCurrentDevice() {
  const el = $("currentDeviceBox");

  const d = VaultState.devices.find(
    x => x.device_id === VaultState.currentDeviceId
  );

  if (!d) {
    el.innerHTML = `<span style="color:#ff5d5d">Not registered</span>`;
    return;
  }

  el.innerHTML = `
    <b>${d.label || "This Device"}</b><br/>
    <small>${d.device_id}</small><br/>
    <span style="color:#2bd576">ACTIVE</span>
  `;
}


/* =========================
   LOAD RECOVERY STATE
========================= */

async function loadRecoveryState() {
  const res = await fetch("/api/recovery/pending", {
    headers: { Authorization: `Bearer ${getToken()}` }
  });

  const data = await res.json();
  return data.pending || [];
}

/* =========================
   DEVICES UI
========================= */

function renderDevices() {
  const el = $("devicesList");
  el.innerHTML = "";

  if (!VaultState.devices.length) {
    el.innerHTML = `<span style="color:#ff5d5d">No devices found</span>`;
    return;
  }
  
  VaultState.devices.forEach(d => {
    const isCurrent = d.device_id === VaultState.currentDeviceId;

    const canApprove =
      VaultState.activeRequest &&
      d.device_id !== VaultState.activeRequest.requester_device_id &&
      d.status === "active";

    const div = document.createElement("div");

    div.className = "device";

    div.innerHTML = `
      <b>${d.label || "Unnamed Device"}</b><br/>
      <small>${d.device_id}</small><br/>
      <span>${d.status}</span><br/><br/>
    
      ${
        d.status === "pending"
          ? `<button data-trust="${d.device_id}" class="primary">
               ${isCurrent ? "Trust this device" : "Pending (other device)"}
             </button>`
          : ""
      }
    
      ${
        d.status === "active"
          ? `<button data-revoke="${d.device_id}" class="danger">Revoke</button>`
          : ""
      }
    
      ${
        canApprove
          ? `<button data-approve="${d.device_id}" class="success">
              🔓 Approve
            </button>`
          : ""
      }
    `;

    el.appendChild(div);
  });

  bindDeviceActions();
}


function renderRecovery() {
  if (!VaultState.activeRequest) {
    setStatus("No active recovery");
    setStep(1);
    setApprovals(0);
    return;
  }

  setStep(2);

  const count = VaultState.approvals;
  setApprovals(count);

  if (count >= VaultState.threshold) {
    setStatus("Quorum reached ✅");
    setStep(3);
  } else {
    setStatus(`Waiting approvals (${count}/${VaultState.threshold})`);
  }
}

/* =========================
   RECOVERY FLOW
========================= */

/* START */

$("startRecoveryBtn").onclick = async () => {
  const res = await fetch("/api/recovery/start", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${getToken()}`,
      "x-qm-device-id": VaultState.currentDeviceId
    }
  });

  const data = await res.json();

  VaultState.activeRequest = {
    request_id: data.request_id,
    requester_device_id: VaultState.currentDeviceId
  };

  setStatus("Recovery started 🚀");
  setStep(2);
};

/* CHECK */
$("checkRecoveryBtn").onclick = async () => {
  const res = await fetch("/api/recovery/pending", {
    headers: { Authorization: `Bearer ${getToken()}` }
  });

  const data = await res.json();

  const requestId =
    window.currentRequestId ||
    localStorage.getItem("qm_recovery_id");

  const req = data.pending.find(r => r.request_id === requestId);

  if (!req) {
    setStatus("Request not found");
    return;
  }

  const approvals = req.approvals || 0;

  setApprovals(approvals);

  if (req.status === "approved") {
    setStatus("Quorum reached ✅");
    setStep(3);
  } else {
    setStatus(`Waiting (${approvals}/2 approvals)`);
  }
};

/* FINISH */
$("finishRecoveryBtn").onclick = async () => {
  setStatus("Completing recovery...");

  const token = getToken();

  const requestId =
    window.currentRequestId ||
    localStorage.getItem("qm_recovery_id");

  if (!requestId) {
    setStatus("Start recovery first ❌");
    return;
  }

  const res = await fetch(`/api/recovery/finish/${requestId}`, {
    headers: { Authorization: `Bearer ${token}` }
  });

  const data = await res.json();

  if (!data.vault) {
    setStatus("Not ready yet ❌");
    return;
  }

  sendToExtension("restore_key", data.vault);

  setStatus("Rewrapping messages...");

  const inboxRes = await fetch("/api/inbox", {
    headers: { Authorization: `Bearer ${token}` }
  });

  const inbox = await inboxRes.json();

  for (const msg of inbox.items || []) {
    sendToExtension("rewrap_message", {
      messageId: msg.id,
      payload: msg
    });
  }

  setStatus("Recovery complete 🎉");
};
