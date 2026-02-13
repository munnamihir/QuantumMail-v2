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

function bytesToBlobUrl(bytesArr, mimeType) {
  const bytes = new Uint8Array(bytesArr || []);
  const blob = new Blob([bytes], { type: mimeType || "application/octet-stream" });
  return URL.createObjectURL(blob);
}

function renderAttachments(list) {
  const host = $("attachments");
  if (!host) return;

  host.innerHTML = "";
  if (!Array.isArray(list) || list.length === 0) return;

  const title = document.createElement("div");
  title.textContent = "Attachments:";
  title.style.marginTop = "10px";
  title.style.fontWeight = "600";
  host.appendChild(title);

  for (const a of list) {
    const url = bytesToBlobUrl(a.bytes, a.mimeType);

    const row = document.createElement("div");
    row.style.marginTop = "6px";

    const link = document.createElement("a");
    link.href = url;
    link.download = a.name || "attachment";
    link.textContent = `⬇ Download ${a.name || "attachment"}`;
    link.style.display = "inline-block";

    row.appendChild(link);
    host.appendChild(row);
  }
}

const msgId = getMsgIdFromPath();
$("msgId").textContent = msgId || "-";

// Auto-fill server base to current origin (keep your existing behavior)
$("serverBase").value = window.location.origin;
$("serverBase").readOnly = true;

function requestDecrypt() {
  ok(""); err("");
  $("out").value = "";
  renderAttachments([]);

  if (!msgId) { err("No message id in URL."); return; }

  const serverBase = window.location.origin;
  const orgId = String($("orgId").value || "").trim();
  const username = String($("username").value || "").trim();
  const password = String($("password").value || "");

  if (!orgId || !username || !password) {
    err("Please enter orgId, username, and password.");
    return;
  }

  setBusy(true);
  ok("Contacting extension…");

  window.postMessage(
    {
      source: "quantummail-portal",
      type: "QM_LOGIN_AND_DECRYPT_REQUEST",
      msgId,
      serverBase,
      orgId,
      username,
      password
    },
    "*"
  );

  // Extension-detection timeout
  const timeout = setTimeout(() => {
    setBusy(false);
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
    ok("Decrypted ✅ (access audited)");
    $("out").value = data.plaintext || "";
    renderAttachments(data.attachments || []);
  } else {
    err(data.error || "Decrypt failed");
    renderAttachments([]);
  }
});

$("btnDecrypt").addEventListener("click", requestDecrypt);
$("password")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") requestDecrypt();
});
