function $(id) {
  return document.getElementById(id);
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

    el.classList.remove("active", "done");

    if (i + 1 < step) el.classList.add("done");
    if (i + 1 === step) el.classList.add("active");
  });
}

function setStatus(text) {
  document.getElementById("recoveryStatusText").textContent = text;
}

function setApprovals(count) {
  document.getElementById("approvalCount").textContent = count;
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

  await renderDevices(data.devices || []);
  await renderCurrentDevice(data.devices || []);
}

async function renderCurrentDevice(devices) {
  const el = $("currentDeviceBox");

  const id = await getDeviceId();

  const d = devices.find(x => x.device_id === id);

  if (!d) {
    el.innerHTML = `
      <span style="color:#ff5d5d">
        Current device not registered
      </span>
    `;
    return;
  }

  el.innerHTML = `
    <b>${d.label || "This Device"}</b><br/>
    ${d.device_id}<br/>
    <span style="color:#2bd576">ACTIVE</span>
  `;
}

/*===========================
  Recovery State
  ===========================*/
async function loadRecoveryState() {
  const res = await fetch("/api/recovery/pending", {
    headers: { Authorization: `Bearer ${getToken()}` }
  });

  const data = await res.json();

  return data.pending || [];
}

/* =========================
   CURRENT DEVICE
========================= */

async function renderDevices(devices) {
  const el = $("devicesList");
  el.innerHTML = "";

  const currentDeviceId = await getDeviceId();
  const pending = await loadRecoveryState();

  // 👉 get active recovery request
  const activeRequest = pending.find(r => r.status === "pending");

  devices.forEach(d => {
    const div = document.createElement("div");
    div.className = "device";

    /* =========================
       TRUST BUTTON (UNCHANGED)
    ========================= */
    const trustBtn =
      d.status === "pending" && d.device_id === currentDeviceId
        ? `<button data-trust="${d.device_id}" class="success">Trust</button>`
        : "";

    /* =========================
       REVOKE BUTTON (UNCHANGED)
    ========================= */
    const revokeBtn =
      d.status === "active"
        ? `<button data-revoke="${d.device_id}" class="danger">Revoke</button>`
        : "";

    /* =========================
       ✅ FIXED APPROVE LOGIC
    ========================= */
    let approveBtn = "";

    if (!activeRequest) {
      // ❌ no recovery started
      approveBtn = `<button disabled style="opacity:.4">No active recovery</button>`;
    } else if (activeRequest.requester_device_id === currentDeviceId) {
      // ❌ Device C (self)
      approveBtn = `<button disabled style="opacity:.4">Your recovery request</button>`;
    } else if (d.device_id === currentDeviceId) {
      // ✅ Only current device can approve
      approveBtn = `
        <button data-approve="${activeRequest.request_id}" class="success">
          🔓 Approve Recovery
        </button>
      `;
    } else {
      // ❌ other rows (just display)
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

  /* =========================
     TRUST HANDLER (KEEP)
  ========================= */
  el.querySelectorAll("[data-trust]").forEach(btn => {
    btn.onclick = async () => {
      const token = getToken();

      await fetch("/api/devices/trust", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          device_id: btn.dataset.trust
        })
      });

      loadDevices();
    };
  });

  /* =========================
     REVOKE HANDLER (KEEP)
  ========================= */
  el.querySelectorAll("[data-revoke]").forEach(btn => {
    btn.onclick = async () => {
      const token = getToken();

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

  /* =========================
     APPROVE HANDLER (FIXED)
  ========================= */
  el.querySelectorAll("[data-approve]").forEach(btn => {
    btn.onclick = async () => {
      const token = getToken();
      const deviceId = await getDeviceId();

      await fetch("/api/recovery/approve", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
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
  const token = getToken();
  const deviceId = await getDeviceId();

  /* =========================
     STEP 1: COMPLETE RECOVERY
  ========================= */
  const res = await fetch(
    `/api/recovery/finish/${window.currentRequestId}`,
    {
      headers: { Authorization: `Bearer ${token}` }
    }
  );

  const data = await res.json();

  if (!data.encrypted_key) {
    $("recoveryStatus").textContent = "Recovery not ready";
    return;
  }

  /* =========================
     STEP 2: SEND KEY TO EXTENSION
  ========================= */
  sendToExtension("restore_key", data);

  /* =========================
     STEP 3: REWRAP ALL MESSAGES
  ========================= */
  const inboxRes = await fetch("/api/inbox", {
    headers: { Authorization: `Bearer ${token}` }
  });

  const inbox = await inboxRes.json();

  for (const msg of inbox.items || []) {
    try {
      const r = await fetch(`/api/messages/${msg.id}/rewrap`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "x-qm-device-id": deviceId
        }
      });

      const payload = await r.json();

      // 🔥 send to extension for rewrap
      sendToExtension("rewrap_message", {
        messageId: msg.id,
        payload
      });

    } catch (e) {
      console.error("rewrap failed for", msg.id);
    }
  }

  $("recoveryStatus").textContent =
    "Recovery complete + messages rewrapped 🎉";
};

$("startRecoveryBtn").onclick = async () => {
  setStep(1);
  setStatus("Starting recovery...");

  const res = await fetch("/api/recovery/start", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${getToken()}`,
      "x-qm-device-id": await getDeviceId()
    }
  });

  const data = await res.json();

  window.currentRequestId = data.request_id;

  setStep(2);
  setStatus("Waiting for approvals...");
  setApprovals(0);
};

$("checkRecoveryBtn").onclick = async () => {
  const res = await fetch("/api/recovery/pending", {
    headers: { Authorization: `Bearer ${getToken()}` }
  });

  const data = await res.json();

  const req = data.pending.find(
    r => r.request_id === window.currentRequestId
  );

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
    setStatus(`Waiting for approvals (${approvals}/2)`);
  }
};

$("finishRecoveryBtn").onclick = async () => {
  setStatus("Completing recovery...");

  const res = await fetch(
    `/api/recovery/finish/${window.currentRequestId}`,
    {
      headers: { Authorization: `Bearer ${getToken()}` }
    }
  );

  const data = await res.json();

  if (!data.encrypted_key) {
    setStatus("Not ready yet ❌");
    return;
  }

  /* SEND TO EXTENSION */
  sendToExtension("restore_key", data);

  setStatus("Rewrapping messages...");

  /* 🔁 REWRAP LOOP */
  const inboxRes = await fetch("/api/inbox", {
    headers: { Authorization: `Bearer ${getToken()}` }
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
