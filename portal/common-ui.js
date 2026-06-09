function injectVaultButton() {
  // Avoid duplicate
  if (document.getElementById("qmVaultBtn")) return;

  const btn = document.createElement("button");
  btn.id = "qmVaultBtn";
  btn.innerHTML = "🔐 Vault";

  btn.style.position = "fixed";
  btn.style.bottom = "20px";
  btn.style.right = "20px";
  btn.style.padding = "10px 14px";
  btn.style.borderRadius = "10px";
  btn.style.border = "1px solid rgba(255,255,255,0.1)";
  btn.style.background = "#12182a";
  btn.style.color = "#e9eefc";
  btn.style.cursor = "pointer";
  btn.style.boxShadow = "0 4px 20px rgba(0,0,0,0.4)";
  btn.style.zIndex = "9999";

  btn.onmouseenter = () => {
    btn.style.background = "#1a2340";
  };

  btn.onmouseleave = () => {
    btn.style.background = "#12182a";
  };

  btn.onclick = () => {
    window.open("/portal/vault.html", "_blank");
  };

  document.body.appendChild(btn);
}

// Auto-run
injectVaultButton();
