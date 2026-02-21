// extension/popup.js
import { normalizeBase, getSession, clearSession } from "./qm.js";

const $ = (id) => document.getElementById(id);

function fmtBytes(n) {
  const x = Number(n || 0);
  if (x < 1024) return `${x} B`;
  const kb = x / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(1)} MB`;
  const gb = mb / 1024;
  return `${gb.toFixed(2)} GB`;
}

function setChosenFiles(files) {
  // store in memory so we can remove individual ones
  window.__qmChosenFiles = files || [];
  renderAttachmentsUI();
}

function getChosenFiles() {
  return Array.isArray(window.__qmChosenFiles) ? window.__qmChosenFiles : [];
}

function renderAttachmentsUI() {
  const list = $("attList");
  const clearBtn = $("btnClearAtt");
  if (!list) return;

  const files = getChosenFiles();
  list.innerHTML = "";

  if (clearBtn) clearBtn.style.display = files.length ? "inline-flex" : "none";

  for (const f of files) {
    const chip = document.createElement("div");
    chip.className = "chip";
    chip.innerHTML = `
      <span class="chipName" title="${f.name}">${f.name}</span>
      <span style="color:var(--muted)">${fmtBytes(f.size)}</span>
      <button type="button" class="chipX" aria-label="Remove ${f.name}">×</button>
    `;

    chip.querySelector(".chipX").addEventListener("click", () => {
      const next = getChosenFiles().filter((x) => !(x.name === f.name && x.size === f.size && x.lastModified === f.lastModified));
      setChosenFiles(next);
    });

    list.appendChild(chip);
  }
}

function setDot(state) {
  const dot = $("dot");
  if (!dot) return;
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

/**
 * IMPORTANT:
 * Read attachments immediately (before any other awaits),
 * otherwise MV3 popup can lose file handle and throw NotReadableError.
 */
async function collectAttachmentsImmediate() {
  const files = getChosenFiles();
  if (!files.length) return [];

  const out = [];
  for (const f of files) {
    try {
      const buf = await f.arrayBuffer();
      out.push({
        name: f.name,
        mimeType: f.type || "application/octet-stream",
        size: f.size,
        bytes: Array.from(new Uint8Array(buf)),
      });
    } catch (e) {
      throw new Error(
        `Could not read "${f.name}". Try re-selecting the file, keep the popup open, and avoid restricted folders. (${e?.name || "ReadError"})`
      );
    }
  }
  return out;
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
    if (!$("username").value) $("username").value = s.user.username || "";
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
  setStatus("Reading attachments…");

  try {
    // ✅ MUST be first to avoid NotReadableError
    const attachments = await collectAttachmentsImmediate();

    setStatus("Encrypting…");

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

    const attNote = attachments.length ? `\nAttachments: ${attachments.length}` : "";
    ok(`Link inserted ✅${attNote}\nWrapped for ${resp.wrappedCount || "many"} org users.${extra}`);
    setStatus("Ready", "good");

    // optional: clear attachments input after encrypt
    //$("attachments").value = "";
    setChosenFiles([]);
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
    err("Set Server Base first.");
    return;
  }
  chrome.tabs.create({ url: `${base}/portal/index.html` });
}

$("btnLogin").addEventListener("click", login);
$("btnLogout").addEventListener("click", logout);
$("btnEncrypt").addEventListener("click", encryptSelected);
$("openAdmin").addEventListener("click", openAdmin);
$("btnAttach")?.addEventListener("click", () => {
  // open OS file picker
  $("attachments")?.click();
});

$("attachments")?.addEventListener("change", (e) => {
  const picked = Array.from(e.target.files || []);
  if (!picked.length) return;

  // append to existing selection (gmail-like)
  const existing = getChosenFiles();
  const merged = [...existing];

  for (const f of picked) {
    // avoid duplicates
    const dup = merged.some((x) => x.name === f.name && x.size === f.size && x.lastModified === f.lastModified);
    if (!dup) merged.push(f);
  }

  setChosenFiles(merged);

  // IMPORTANT: reset input so selecting same file again triggers change
  e.target.value = "";
});

$("btnClearAtt")?.addEventListener("click", () => {
  setChosenFiles([]);
  $("attachments").value = "";
});
(async function init() {
  fillDefaults();
  setChosenFiles([]);
  await refreshSessionUI();
})();
