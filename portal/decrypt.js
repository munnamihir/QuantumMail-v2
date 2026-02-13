const $ = (id) => document.getElementById(id);

function getMsgIdFromPath() {
  const parts = location.pathname.split("/").filter(Boolean);
  if (parts[0] === "m" && parts[1]) return parts[1];
  return "";
}

function ok(msg) { $("ok").textContent = msg || ""; }
function err(msg) { $("err").textContent = msg || ""; }

function setBusy(busy) {
  const btn = $("btnDecrypt");
  btn.disabled = !!busy;
  btn.textContent = busy ? "Decrypting…" : "Decrypt";
}

function setExtStatus(text, state /* good|bad|null */) {
  const dot = $("extDot");
  const label = $("extStatus");
  if (label) label.textContent = text || "";

  if (dot) {
    dot.classList.remove("good", "bad");
    if (state === "good") dot.classList.add("good");
    if (state === "bad") dot.classList.add("bad");
  }
}

function humanKB(n) {
  const kb = Math.round((Number(n || 0) / 1024) * 10) / 10;
  if (!kb) return "—";
  if (kb < 1024) return `${kb} KB`;
  const mb = Math.round((kb / 1024) * 10) / 10;
  return `${mb} MB`;
}

function bytesToBlobUrl(bytesArr, mimeType) {
  const bytes = new Uint8Array(bytesArr || []);
  const blob = new Blob([bytes], { type: mimeType || "application/octet-stream" });
  return URL.createObjectURL(blob);
}

function clearAttachmentsUI() {
  const host = $("attachments");
  if (host) host.innerHTML = "";
}

function renderAttachments(list) {
  const host = $("attachments");
  if (!host) return;

  host.innerHTML = "";
  if (!Array.isArray(list) || list.length === 0) {
    host.innerHTML = `<div class="muted" style="font-size:12px;">No attachments</div>`;
    return;
  }

  for (const a of list) {
    const url = bytesToBlobUrl(a.bytes, a.mimeType);

    const card = document.createElement("div");
    card.className = "attCard";

    const meta = document.createElement("div");
    meta.className = "attMeta";

    const name = document.createElement("div");
    name.className = "attName";
    name.textContent = a.name || "attachment";

    const sub = document.createElement("div");
    sub.className = "attSub";
    sub.textContent = `${a.mimeType || "application/octet-stream"} • ${humanKB(a.size)}`;

    meta.appendChild(name);
    meta.appendChild(sub);

    const link = document.createElement("a");
    link.className = "attBtn";
    link.href = url;
    link.download = a.name || "attachment";
    link.textContent = "⬇ Download";

    card.appendChild(meta);
    card.appendChild(link);
    host.appendChild(card);
  }
}

function syncModeUI(mode) {
  $("pqcFields").style.display = (mode === "pqc") ? "" : "none";
  $("pwFields").style.display = (mode === "passphrase") ? "" : "none";
}

const msgId = getMsgIdFromPath();
$("msgId").textContent = msgId || "-";

$("mode").addEventListener("change", () => syncModeUI($("mode").value));
syncModeUI($("mode").value);

function requestDecrypt() {
  ok(""); err("");
  $("out").value = "";
  clearAttachmentsUI();

  if (!msgId) {
    err("No message id in URL.");
    setExtStatus("Missing message id", "bad");
    return;
  }

  const serverBase = window.location.origin;
  const orgId = String($("orgId").value || "").trim();
  const username = String($("username").value || "").trim();
  const password = String($("password").value || "");
  const mode = String($("mode").value || "pqc");

  // Optional fields depending on mode
  const recipientSk = String($("recipientSk")?.value || "");
  const passphrase = String($("passphrase")?.value || "");

  if (!orgId || !username || !password) {
    err("Please enter orgId, username, and password.");
    setExtStatus("Waiting for login", null);
    return;
  }

  // If you want the decrypt page to still support PQC/passphrase UI:
  // we pass these to extension; extension can ignore if not needed.
  const extra = {
    mode,
    recipientSk,
    passphrase
  };

  setBusy(true);
  setExtStatus("Contacting extension…", null);
  ok("Contacting extension…");

  window.postMessage(
    {
      source: "quantummail-portal",
      type: "QM_LOGIN_AND_DECRYPT_REQUEST",
      msgId,
      serverBase,
      orgId,
      username,
      password,
      ...extra
    },
    "*"
  );

  // Extension-detection timeout
  const timeout = setTimeout(() => {
    setBusy(false);
    setExtStatus("Extension not detected", "bad");
    err(
      "QuantumMail extension not detected.\n" +
      "1) Install/enable the extension\n" +
      "2) Refresh this page\n" +
      "3) Try again"
    );
  }, 5000);

  window.__qmDecryptTimeout = timeout;
}

window.addEventListener("message", (event) => {
  const data = event.data || {};
  if (data?.source !== "quantummail-extension") return;
  if (data?.type !== "QM_DECRYPT_RESULT") return;

  if (window.__qmDecryptTimeout) {
    clearTimeout(window.__qmDecryptTimeout);
    window.__qmDecryptTimeout = null;
  }

  setBusy(false);

  if (data.ok) {
    setExtStatus("Extension connected", "good");
    ok(`Decrypted ✅${Array.isArray(data.attachments) && data.attachments.length ? ` (${data.attachments.length} attachment(s))` : ""}`);
    $("out").value = data.plaintext || "";
    renderAttachments(data.attachments || []);
  } else {
    setExtStatus("Decrypt failed", "bad");
    err(data.error || "Decrypt failed");
    renderAttachments([]);
  }
});

$("btnDecrypt").addEventListener("click", requestDecrypt);
$("password")?.addEventListener("keydown", (e) => { if (e.key === "Enter") requestDecrypt(); });
$("recipientSk")?.addEventListener("keydown", (e) => { if (e.key === "Enter") requestDecrypt(); });
$("passphrase")?.addEventListener("keydown", (e) => { if (e.key === "Enter") requestDecrypt(); });
