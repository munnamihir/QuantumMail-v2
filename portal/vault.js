// portal/vault.js
function sendToExtension(type, payload) {
  window.postMessage({ source: "qm-portal", type, payload }, "*");
}

function $(id) {
  return document.getElementById(id);
}

function setStatus(s) {
  const el = $("status");
  if (el) el.textContent = String(s || "");
}

function parseToken(tokenString) {
  const parts = String(tokenString || "").trim().split("|");
  if (parts.length !== 3 || parts[0] !== "qm-rrt-2") return null;
  return { token_id: parts[1], token_secret: parts[2] };
}

function setField(id, val) {
  const el = $(id);
  if (el) el.value = val ?? "";
}

function getField(id) {
  const el = $(id);
  return el ? String(el.value || "").trim() : "";
}

function setPre(id, obj) {
  const el = $(id);
  if (!el) return;
  el.textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
}

function enableBtn(id, enabled) {
  const el = $(id);
  if (el) el.disabled = !enabled;
}

function setStep(step) {
  // steps: "ready" | "vault_enabled" | "started" | "approved" | "finished"
  // purely UI toggles; no logic depends on this
  if (step === "ready") {
    enableBtn("approveBtn", true);
    enableBtn("finishBtn", true);
  }
}

window.addEventListener("message", (event) => {
  const msg = event.data;
  if (!msg || msg.source !== "qm-ext") return;

  if (msg.type === "vault_enabled") {
    const tok = msg.payload?.token_display || "(no token returned)";
    setPre("tokenOut", tok);
    setStatus("Vault enabled. Save your token NOW (only time you’ll see it).");
    setStep("vault_enabled");
  }

  if (msg.type === "recovery_started") {
    const payload = msg.payload || {};
    const request_id = payload.request_id;
    const nonce_b64 = payload.nonce_b64;

    // Put into UI fields so user can copy to trusted device
    setField("reqId", request_id || "");
    setField("nonce", nonce_b64 || "");

    setPre("reqOut", { request_id, nonce_b64 });
    setStatus("Recovery request started. Copy Request ID + Nonce to your trusted device and approve there.");
    setStep("started");
  }

  if (msg.type === "recovery_approved") {
    setStatus("Approved ✅ Now go back to the NEW device and click Finish Recovery.");
    setStep("approved");
  }

  if (msg.type === "vault_recovered") {
    setStatus("Recovery successful ✅ You can decrypt old links again.");
    setStep("finished");
  }

  if (msg.type === "vault_error") {
    setStatus("Error: " + (msg.payload?.error || "unknown"));
  }
});

/** =========================
 * UI actions
 * ========================= */

$("enableBtn").onclick = () => {
  setStatus("Enabling vault...");
  sendToExtension("enable_vault", {});
};

$("startBtn").onclick = () => {
  const token = getField("tokenIn");
  const parsed = parseToken(token);
  if (!parsed) return setStatus("Paste a valid token: qm-rrt-2|token_id|token_secret");

  setStatus("Starting recovery request on this NEW device...");
  // Start creates request_id + nonce. That’s what you paste into trusted device.
  sendToExtension("start_recovery", { token });
};

// This is used on TRUSTED DEVICE.
// It should NOT rely on "lastRecovery" from the device that started it.
$("approveBtn").onclick = () => {
  const request_id = getField("reqId");
  const nonce_b64 = getField("nonce");
  if (!request_id || !nonce_b64) {
    return setStatus("Paste Request ID + Nonce (from the new device) before approving.");
  }
  setStatus("Approving request on this TRUSTED device...");
  sendToExtension("approve_recovery", { request_id, nonce_b64 });
};

// This is used on NEW DEVICE after trusted device approved.
// It uses token + request_id (nonce not required for finish).
$("finishBtn").onclick = () => {
  const token = getField("tokenIn");
  const parsed = parseToken(token);
  if (!parsed) return setStatus("Paste a valid token: qm-rrt-2|token_id|token_secret");

  const request_id = getField("reqId");
  if (!request_id) return setStatus("Request ID required. Paste it from Step A output.");

  setStatus("Finishing recovery on NEW device (fetching vault + restoring key)...");
  sendToExtension("finish_recovery", {
    request_id,
    token_id: parsed.token_id,
    token_secret: parsed.token_secret
  });
};

// initial state
setStep("ready");
setStatus("Ready.");
