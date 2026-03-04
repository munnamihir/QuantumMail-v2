// portal/vault.js

function sendToExtension(type, payload) {
  window.postMessage({ source: "qm-portal", type, payload }, "*");
}

function $(id) {
  return document.getElementById(id);
}

function setStatus(s, kind = "muted") {
  const el = $("status");
  el.textContent = s;

  el.classList.remove("ok", "err", "muted");
  if (kind === "ok") el.classList.add("ok");
  else if (kind === "err") el.classList.add("err");
  else el.classList.add("muted");
}

function pretty(obj) {
  return JSON.stringify(obj, null, 2);
}

let lastRecovery = null; // { request_id, nonce_b64, token_id, token_secret }
let lastPending = null;  // { request_id, nonce_b64 }

function setPendingUI(pending) {
  lastPending = pending || null;
  if (!pending) {
    $("pendingOut").textContent = "(none)";
    $("approveBtn").disabled = true;
    return;
  }
  $("pendingOut").textContent = pretty(pending);
  $("approveBtn").disabled = false;
}

function clearRecoveryUI() {
  lastRecovery = null;
  $("reqOut").textContent = "(none)";
  $("finishBtn").disabled = true;
}

window.addEventListener("message", (event) => {
  const msg = event.data;
  if (!msg || msg.source !== "qm-ext") return;

  if (msg.type === "vault_enabled") {
    $("tokenOut").textContent = msg.payload.token_display;
    setStatus("Vault enabled ✅ Save your token NOW (this is the only time you’ll see it).", "ok");
  }

  if (msg.type === "recovery_started") {
    lastRecovery = msg.payload;

    $("reqOut").textContent = pretty({
      request_id: lastRecovery.request_id,
      nonce_b64: lastRecovery.nonce_b64
    });

    // ✅ IMPORTANT: do NOT enable approve here
    // Approve is meant for TRUSTED DEVICE page.
    $("finishBtn").disabled = false;

    setStatus(
      "Recovery request started ✅ Now open this Vault page on a TRUSTED device/profile and click “Load Pending Requests” → Approve. Then come back here and click Finish.",
      "ok"
    );
  }

  if (msg.type === "pending_loaded") {
    // payload: { request_id, nonce_b64 } or null
    setPendingUI(msg.payload?.pending || null);
    if (msg.payload?.pending) {
      setStatus("Pending request loaded. If this is your TRUSTED device, you can approve it.", "ok");
    } else {
      setStatus("No pending requests found for your account.", "muted");
    }
  }

  if (msg.type === "recovery_approved") {
    setStatus("Approved ✅ Now go back to the NEW device/profile and click Finish Recovery.", "ok");
  }

  if (msg.type === "vault_recovered") {
    setStatus("Recovery successful ✅ You can decrypt old links again.", "ok");
  }

  if (msg.type === "vault_error") {
    setStatus("Error: " + msg.payload.error, "err");
  }
});

/* =========================
   Button handlers
========================= */

$("enableBtn").onclick = () => {
  setStatus("Enabling vault…");
  sendToExtension("enable_vault", {});
};

$("startBtn").onclick = () => {
  const token = $("tokenIn").value.trim();
  if (!token) return setStatus("Paste your token first.", "err");

  clearRecoveryUI();
  setPendingUI(null);

  setStatus("Starting recovery request…");
  sendToExtension("start_recovery", { token });
};

$("loadPendingBtn").onclick = () => {
  setStatus("Loading pending requests…");
  sendToExtension("recovery_pending", {});
};

$("approveBtn").onclick = () => {
  if (!lastPending) return setStatus("No pending request loaded to approve.", "err");

  setStatus("Approving recovery request (this must be on a TRUSTED device)…");
  sendToExtension("approve_recovery", {
    request_id: lastPending.request_id,
    nonce_b64: lastPending.nonce_b64
  });
};

$("finishBtn").onclick = () => {
  if (!lastRecovery) return setStatus("No recovery request to finish.", "err");

  setStatus("Finishing recovery (fetching vault + restoring key)…");
  sendToExtension("finish_recovery", {
    request_id: lastRecovery.request_id,
    token_id: lastRecovery.token_id,
    token_secret: lastRecovery.token_secret
  });
};

/* =========================
   Initial UI state
========================= */
$("approveBtn").disabled = true;
$("finishBtn").disabled = true;
setPendingUI(null);
clearRecoveryUI();
