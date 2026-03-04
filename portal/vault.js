function sendToExtension(type, payload) {
  window.postMessage({ source: "qm-portal", type, payload }, "*");
}

window.addEventListener("message", (event) => {
  const msg = event.data;
  if (!msg || msg.source !== "qm-ext") return;

  if (msg.type === "vault_enabled") {
    document.getElementById("tokenOut").textContent = msg.payload.token_display;
    setStatus("Vault enabled. Save your token now.");
  }

  if (msg.type === "vault_recovered") {
    setStatus("Recovery successful. You can decrypt again.");
  }

  if (msg.type === "vault_error") {
    setStatus("Error: " + msg.payload.error);
  }
});

function setStatus(s) {
  document.getElementById("status").textContent = s;
}

document.getElementById("enableBtn").onclick = () => {
  setStatus("Enabling vault...");
  sendToExtension("enable_vault", {});
};

document.getElementById("recoverBtn").onclick = () => {
  const token = document.getElementById("tokenIn").value.trim();
  setStatus("Recovering...");
  sendToExtension("recover_vault", { token });
};
