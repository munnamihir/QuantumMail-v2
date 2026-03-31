function $(id) {
  return document.getElementById(id);
}

function sendToExtension(type, payload = {}) {
  window.postMessage({ source: "qm-portal", type, payload }, "*");
}

document.addEventListener("DOMContentLoaded", () => {
  loadDevices();
});

function loadDevices() {
  sendToExtension("load_devices");
}

function renderDevices(devices) {
  const el = $("devicesList");
  el.innerHTML = "";

  devices.forEach(d => {
    const div = document.createElement("div");

    div.innerHTML = `
      <div style="border:1px solid #444; padding:12px; margin:10px;">
        <b>${d.label || "Device"}</b><br/>
        ${d.device_id}<br/>
        Status: ${d.status}<br/><br/>

        ${
          d.status === "pending"
            ? `<button data-trust="${d.device_id}">Trust</button>`
            : ""
        }

        ${
          d.status === "active"
            ? `<button data-revoke="${d.device_id}">Revoke</button>`
            : ""
        }
      </div>
    `;

    el.appendChild(div);
  });

  el.querySelectorAll("[data-trust]").forEach(btn => {
    btn.onclick = () => {
      sendToExtension("trust_this_device", {
        device_id: btn.dataset.trust
      });
    };
  });

  el.querySelectorAll("[data-revoke]").forEach(btn => {
    btn.onclick = () => {
      sendToExtension("revoke_device", {
        device_id: btn.dataset.revoke
      });
    };
  });
}

/* START RECOVERY */
$("startBtn").onclick = () => {
  sendToExtension("start_recovery");
};

/* LOAD PENDING */
$("loadPendingBtn").onclick = () => {
  sendToExtension("load_pending");
};

/* FINISH */
$("finishBtn").onclick = () => {
  sendToExtension("finish_recovery", {
    request_id: lastRecovery.request_id
  });
};

window.addEventListener("message", (event) => {
  const msg = event.data;
  if (!msg || msg.source !== "qm-ext") return;

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
});


window.addEventListener("message", (event) => {
  const msg = event.data;
  if (!msg || msg.source !== "qm-ext") return;

  if (msg.type === "devices_loaded") {
    renderDevices(msg.payload.devices);
  }

  if (msg.type === "device_trusted" || msg.type === "device_revoked") {
    loadDevices();
  }
});
