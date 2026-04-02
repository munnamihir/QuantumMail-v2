/* =========================
   HELPERS
========================= */

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
    window.postMessage(
      { source: "qm-portal", type: "GET_DEVICE_ID" },
      "*"
    );

    window.addEventListener("message", function handler(event) {
      if (event.data?.type === "QM_DEVICE_ID_RESPONSE") {
        window.removeEventListener("message", handler);
        resolve(event.data.deviceId);
      }
    });
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
  const res = await fetch("/api/devices/list", {
    headers: { Authorization: `Bearer ${getToken()}` }
  });

  const data = await res.json();

  await renderDevices(data.devices || []);
  await renderCurrentDevice(data.devices || []);
}

/* =========================
   CURRENT DEVICE
========================= */

async function renderCurrentDevice(devices) {
  const el = $("currentDeviceBox");
  const id = await getDeviceId();

  const d = devices.find(x => x.device_id === id);

  if (!d) {
    el.innerHTML = `<span style="color:#ff5d5d">Current device not registered</span>`;
    return;
  }

  el.innerHTML = `
    <b>${d.label || "This Device"}</b><br/>
    ${d.device_id}<br/>
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

async function renderDevices(devices) {
  const el = $("devicesList");
  el.innerHTML = "";

  const currentDeviceId = await getDeviceId();
  const pending = await loadRecoveryState();
  const activeRequest = pending.find(r => r.status === "pending");

  devices.forEach(d => {
    const div = document.createElement("div");
    div.className = "device";

    const trustBtn =
      d.status === "pending" && d.device_id === currentDeviceId
        ? `<button data-trust="${d.device_id}" class="success">Trust</button>`
        : "";

    const revokeBtn =
      d.status === "active"
        ? `<button data-revoke="${d.device_id}" class="danger">Revoke</button>`
        : "";

    let approveBtn = "";

    if (!activeRequest) {
      approveBtn = `<button disabled style="opacity:.4">No active recovery</button>`;
    } else if (activeRequest.requester_device_id === currentDeviceId) {
      approveBtn = `<button disabled style="opacity:.4">Your request</button>`;
    } else if (d.device_id === currentDeviceId) {
      approveBtn = `
        <button data-approve="${activeRequest.request_id}" class="success">
          🔓 Approve Recovery
        </button>`;
    } else {
      approveBtn = `<button disabled style="opacity:.4">Not this device</button>`;
    }

    div.innerHTML = `
      <b>${d.label || "Device"}</b><br/>
      ${d.device_id}<br/>
      <span>${d.status}</span><br/><br/>

      ${trustBtn}
      ${revokeBtn}
      ${approveBtn}
    `;

    el.appendChild(div);
  });

  /* TRUST */
  el.querySelectorAll("[data-trust]").forEach(btn => {
    btn.onclick = async () => {
      await fetch("/api/devices/trust", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${getToken()}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ device_id: btn.dataset.trust })
      });

      loadDevices();
    };
  });

  /* REVOKE */
  el.querySelectorAll("[data-revoke]").forEach(btn => {
    btn.onclick = async () => {
      await fetch("/api/devices/revoke", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${getToken()}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ device_id: btn.dataset.revoke })
      });

      loadDevices();
    };
  });

  /* APPROVE */
  el.querySelectorAll("[data-approve]").forEach(btn => {
    btn.onclick = async () => {
      const deviceId = await getDeviceId();

      await fetch("/api/recovery/approve", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${getToken()}`,
          "Content-Type": "application/json",
          "x-qm-device-id": deviceId
        },
        body: JSON.stringify({
          request_id: btn.dataset.approve
        })
      });

      alert("✅ Approved");
    };
  });
}

/* =========================
   RECOVERY FLOW
========================= */

/* START */
$("startRecoveryBtn").onclick = async () => {
  setStep(1);
  setStatus("Starting recovery...");

  const deviceId = await getDeviceId();

  const res = await fetch("/api/recovery/start", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${getToken()}`,
      "x-qm-device-id": deviceId
    }
  });

  const data = await res.json();

  if (!data.request_id) {
    setStatus("Failed to start recovery ❌");
    return;
  }

  window.currentRequestId = data.request_id;
  localStorage.setItem("qm_recovery_id", data.request_id);

  setStep(2);
  setStatus("Waiting for approvals...");
  setApprovals(0);
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

  sendToExtension("QM_RESTORE_KEY", data,vault);

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
