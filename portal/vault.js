function $(id) {
  return document.getElementById(id);
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
function loadDevices() {
  console.log("Loading devices...");
  sendToExtension("load_devices");
}

/* =========================
   RENDER DEVICES
========================= */
function renderDevices(devices) {
  const el = $("devicesList");
  el.innerHTML = "";

  if (!devices || !devices.length) {
    el.innerHTML = `<div style="opacity:.7">No devices found</div>`;
    return;
  }

  devices.forEach(d => {
    const div = document.createElement("div");

    const statusColor =
      d.status === "active"
        ? "#2bd576"
        : d.status === "pending"
        ? "#facc15"
        : "#ef4444";

    div.innerHTML = `
      <div style="
        border:1px solid #444;
        padding:14px;
        margin:10px;
        border-radius:10px;
        background:#0f172a;
      ">
        <b style="font-size:14px">${d.label || "Device"}</b><br/>
        <span style="opacity:.6">${d.device_id}</span><br/>

        <span style="color:${statusColor}; font-weight:bold;">
          ${d.status.toUpperCase()}
        </span><br/><br/>

        ${
          d.status === "pending"
            ? `<button data-trust="${d.device_id}" class="btn">Trust</button>`
            : ""
        }

        ${
          d.status === "active"
            ? `<button data-revoke="${d.device_id}" class="btn danger">Revoke</button>`
            : ""
        }
      </div>
    `;

    el.appendChild(div);
  });

  /* =========================
     TRUST BUTTON
  ========================= */
  el.querySelectorAll("[data-trust]").forEach(btn => {
    btn.onclick = () => {
      const id = btn.dataset.trust;
      console.log("Trust clicked:", id);

      sendToExtension("trust_this_device", {
        device_id: id
      });
    };
  });

  /* =========================
     REVOKE BUTTON
  ========================= */
  el.querySelectorAll("[data-revoke]").forEach(btn => {
    btn.onclick = () => {
      const id = btn.dataset.revoke;
      console.log("Revoke clicked:", id);

      sendToExtension("revoke_device", {
        device_id: id
      });
    };
  });
}

/* =========================
   RECOVERY BUTTONS
========================= */

let lastRecovery = null;

$("startBtn")?.addEventListener("click", () => {
  sendToExtension("start_recovery");
});

$("loadPendingBtn")?.addEventListener("click", () => {
  sendToExtension("load_pending");
});

$("finishBtn")?.addEventListener("click", () => {
  if (!lastRecovery) return;

  sendToExtension("finish_recovery", {
    request_id: lastRecovery.request_id
  });
});

/* =========================
   MESSAGE LISTENER
========================= */
window.addEventListener("message", (event) => {
  const msg = event.data;
  if (!msg || msg.source !== "qm-ext") return;

  console.log("Vault received:", msg);

  /* DEVICES */
  if (msg.type === "devices_loaded") {
    renderDevices(msg.payload.devices);
  }

  if (msg.type === "device_trusted") {
    console.log("Device trusted!");
    loadDevices();
  }

  if (msg.type === "device_revoked") {
    console.log("Device revoked!");
    loadDevices();
  }

  /* RECOVERY */
  if (msg.type === "recovery_started") {
    lastRecovery = msg.payload;
    $("reqOut").textContent = JSON.stringify(msg.payload, null, 2);
  }

  if (msg.type === "pending_loaded") {
    renderPending(msg.payload.pending);
  }

  if (msg.type === "recovery_approved") {
    $("approveMsg").textContent = "Approved!";
  }

  if (msg.type === "vault_recovered") {
    $("recoverMsg").textContent = "Recovery complete!";
  }

  if (msg.type === "vault_error") {
    alert(msg.payload.error);
  }
});

btn.onclick = () => {
  const id = btn.dataset.trust;
  console.log("🚀 Sending trust for:", id);

  sendToExtension("trust_this_device", {
    device_id: id
  });
};
