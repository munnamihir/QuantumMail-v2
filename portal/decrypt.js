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
  btn.textContent = busy ? "Decrypting…" : "Login & Decrypt";
}

function bytesToBlobUrl(bytesArr, mimeType) {
  const bytes = new Uint8Array(bytesArr || []);
  const blob = new Blob([bytes], { type: mimeType || "application/octet-stream" });
  return URL.createObjectURL(blob);
}

function renderAttachments(list) {
  const wrap = $("attachments");
  const host = $("attList");
  if (!wrap || !host) return;

  host.innerHTML = "";
  if (!Array.isArray(list) || list.length === 0) {
    wrap.style.display = "none";
    return;
  }

  wrap.style.display = "";
  for (const a of list) {
    const url = bytesToBlobUrl(a.bytes, a.mimeType);
    const row = document.createElement("div");
    row.className = "attItem";

    const link = document.createElement("a");
    link.href = url;
    link.download = a.name || "attachment";
    const kb = a.size ? Math.round(a.size / 1024) : null;
    link.textContent = `⬇ ${a.name || "attachment"}${kb ? ` • ${kb} KB` : ""}`;

    row.appendChild(link);
    host.appendChild(row);
  }
}

const msgId = getMsgIdFromPath();
$("msgId").textContent = msgId || "-";

function requestDecrypt() {
  ok(""); err("");
  $("out").value = "";
  renderAttachments([]);

  if (!msgId) { err("No message id in URL."); return; }

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
      serverBase: window.location.origin, // same origin API
      orgId,
      username,
      password
    },
    "*"
  );

  // extension-detection timeout
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
    ok(data.message || "Decrypted ✅ (access audited)");
    $("out").value = data.plaintext || "";
    renderAttachments(data.attachments || []);
  } else {
    err(data.error || "Decrypt failed");
    renderAttachments([]);
  }
});

$("btnDecrypt").addEventListener("click", requestDecrypt);
$("password")?.addEventListener("keydown", (e) => { if (e.key === "Enter") requestDecrypt(); });
