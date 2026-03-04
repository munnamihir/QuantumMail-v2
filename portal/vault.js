// portal/vault.js
function sendToExtension(type, payload) {
  window.postMessage({ source: "qm-portal", type, payload }, "*");
}

function $(id) {
  return document.getElementById(id);
}

function setStatus(s) {
  $("status").textContent = s;
}

let lastRecovery = null; // { request_id, nonce_b64, token_id, token_secret }

window.addEventListener("message", (event) => {
  const msg = event.data;
  if (!msg || msg.source !== "qm-ext") return;

  if (msg.type === "vault_enabled") {
    $("tokenOut").textContent = msg.payload.token_display;
    setStatus("Vault enabled. Save your token NOW (only time you’ll see it).");
  }

  if (msg.type === "recovery_started") {
    lastRecovery = msg.payload;
    $("reqOut").textContent = JSON.stringify(
      { request_id: lastRecovery.request_id, nonce_b64: lastRecovery.nonce_b64 },
      null,
      2
    );
    $("approveBtn").disabled = false;
    $("finishBtn").disabled = false;
    setStatus("Recovery request started. Now approve it on another trusted device.");
  }

  if (msg.type === "recovery_approved") {
    setStatus("Approved. Now go back to the NEW device and click Finish Recovery.");
  }

  if (msg.type === "vault_recovered") {
    setStatus("Recovery successful. You can decrypt old links again.");
  }

  if (msg.type === "vault_error") {
    setStatus("Error: " + msg.payload.error);
  }
});

$("enableBtn").onclick = () => {
  setStatus("Enabling vault...");
  sendToExtension("enable_vault", {});
};

$("startBtn").onclick = () => {
  const token = $("tokenIn").value.trim();
  if (!token) return setStatus("Paste your token first.");
  setStatus("Starting recovery request...");
  sendToExtension("start_recovery", { token });
};

$("approveBtn").onclick = () => {
  if (!lastRecovery) return setStatus("No request to approve.");
  setStatus("Approving recovery request (this must be on a trusted device)...");
  sendToExtension("approve_recovery", {
    request_id: lastRecovery.request_id,
    nonce_b64: lastRecovery.nonce_b64
  });
};

$("finishBtn").onclick = () => {
  if (!lastRecovery) return setStatus("No request to finish.");
  setStatus("Finishing recovery (fetching vault + restoring key)...");
  sendToExtension("finish_recovery", {
    request_id: lastRecovery.request_id,
    token_id: lastRecovery.token_id,
    token_secret: lastRecovery.token_secret
  });
};
