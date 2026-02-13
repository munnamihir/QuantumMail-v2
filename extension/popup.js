// extension/popup.js
import { normalizeBase, getSession, clearSession } from "./qm.js";

const $ = (id) => document.getElementById(id);

async function readFileToArrayBuffer(file) {
  // try native first
  try {
    return await file.arrayBuffer();
  } catch (e) {
    // fallback FileReader (often succeeds where arrayBuffer fails)
    return await new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onerror = () => reject(r.error || e);
      r.onload = () => resolve(r.result);
      r.readAsArrayBuffer(file);
    });
  }
}

async function collectAttachmentsImmediate() {
  const input = $("attachments");
  if (!input || !input.files || input.files.length === 0) return [];

  const files = Array.from(input.files);

  const out = [];
  for (const f of files) {
    if (!f.size) {
      throw new Error(`"${f.name}" is empty or not fully downloaded. Try "Download Now" (iCloud) then re-select.`);
    }

    try {
      const buf = await readFileToArrayBuffer(f);
      out.push({
        name: f.name,
        mimeType: f.type || "application/octet-stream",
        size: f.size,
        bytes: Array.from(new Uint8Array(buf))
      });
    } catch (e) {
      throw new Error(
        `Could not read "${f.name}". Move it to a local folder (Documents/Desktop), ensure it's downloaded (no iCloud cloud icon), then re-select. (${e?.name || "ReadError"})`
      );
    }
  }

  return out;
}

function setDot(state) {
  const dot = $("dot");
  dot.classList.remove("good", "bad");
  if (state === "good") dot.classList.add("good");
  if (state === "bad") dot.classList.add("bad");
}

function setStatus(text, state = null) {
  $("status").textContent = text || "";
  if (state) setDot(state);
}

function ok(msg) {
  $("ok").textContent = msg || "";
  if (msg) $("err").textContent = "";
}

function err(msg) {
  $("err").textContent = msg || "";
  if (msg) $("ok").textContent = "";
  setDot("bad");
}

async function sendBg(type, payload = {}) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type, ...payload }, (resp) => resolve(resp));
  });
}

function fillDefaults() {
  if (!$("orgId").value) $("orgId").value = "org_demo";
}

async function refreshSessionUI() {
  const s = await getSession();
  const who = $("who");

  if (s?.token && s?.user) {
    who.textContent = `${s.user.username}@${s.user.orgId || "org"}`;
    setStatus("Signed in", "good");
    if (!$("serverBase").value && s.serverBase) $("serverBase").value = s.serverBase;
    if (!$("orgId").value && s.user.orgId) $("orgId").value = s.user.orgId;
    $("username").value = s.user.username || $("username").value;
  } else {
    who.textContent = "Signed out";
    setStatus("Not signed in");
    setDot(null);
  }
}

async function login() {
  ok(""); $("err").textContent = "";
  setStatus("Signing in…");

  const serverBase = normalizeBase($("serverBase").value.trim());
  const orgId = $("orgId").value.trim();
  const username = $("username").value.trim();
  const password = $("password").value;

  if (!serverBase || !orgId || !username || !password) {
    err("serverBase, orgId, username, and password are required.");
    return;
  }

  const resp = await sendBg("QM_LOGIN", { serverBase, orgId, username, password });
  if (!resp?.ok) {
    err(resp?.error || "Login failed");
    return;
  }

  ok("Logged in ✅ Public key registered.");
  await refreshSessionUI();
}

async function logout() {
  ok(""); $("err").textContent = "";
  await clearSession();
  ok("Logged out.");
  await refreshSessionUI();
}

async function encryptSelected() {
  ok(""); $("err").textContent = "";
  setStatus("Encrypting…");

  try {
    // ✅ read attachments first (prevents NotReadableError from popup losing handle)
    const attachments = await collectAttachmentsImmediate();

    const s = await getSession();
    if (!s?.token) {
      err("Please login first.");
      setStatus("Not signed in", "bad");
      return;
    }

    const resp = await sendBg("QM_ENCRYPT_SELECTION", { attachments });
    if (!resp?.ok) {
      err(resp?.error || "Encrypt failed");
      setStatus("Error", "bad");
      return;
    }

    const extra =
      (typeof resp.skippedNoKey === "number" && resp.skippedNoKey > 0)
        ? `\nSkipped ${resp.skippedNoKey} users (no public key yet).`
        : "";

    ok(`Link inserted ✅\nWrapped for ${resp.wrappedCount || "many"} org users.${extra}`);
    setStatus("Ready", "good");
  } catch (e) {
    console.error(e);
    err(e?.message || String(e));
    setStatus("Error", "bad");
  }
}

async function openAdmin() {
  const s = await getSession();
  const base = s?.serverBase || normalizeBase($("serverBase").value.trim());
  if (!base) {
    err("Set Server Base first (your server URL).");
    return;
  }
  chrome.tabs.create({ url: `${base}/portal/admin.html` });
}

$("btnLogin").addEventListener("click", login);
$("btnLogout").addEventListener("click", logout);
$("btnEncrypt").addEventListener("click", encryptSelected);
$("openAdmin").addEventListener("click", openAdmin);

(async function init() {
  fillDefaults();
  await refreshSessionUI();
})();
