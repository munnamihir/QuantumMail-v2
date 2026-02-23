// extension/popup.js
import { normalizeBase, getSession, clearSession } from "./qm.js";

const $ = (id) => document.getElementById(id);
const DEFAULT_SERVER_BASE = "https://quantummail-v2.onrender.com";
/** ===== Attachment state (appendable) ===== */
let selectedFiles = []; // Array<File>

let orgUsers = [];          // [{userId, username, hasKey}]
let selectedRecipients = []; // [{userId, username}]

function esc(s){ return String(s||"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;"); }

function renderRecipientChips() {
  const host = $("rcptChips");
  if (!host) return;
  host.innerHTML = "";

  selectedRecipients.forEach((r, idx) => {
    const chip = document.createElement("div");
    chip.className = "chip";

    const name = document.createElement("div");
    name.className = "chipName";
    name.textContent = r.username;

    const x = document.createElement("div");
    x.className = "chipX";
    x.textContent = "×";
    x.title = "Remove";
    x.addEventListener("click", () => {
      selectedRecipients.splice(idx, 1);
      renderRecipientChips();
    });

    chip.appendChild(name);
    chip.appendChild(x);
    host.appendChild(chip);
  });
}

function hideSuggest() {
  const box = $("rcptSuggest");
  if (box) box.style.display = "none";
  if (box) box.innerHTML = "";
}

function showSuggest(matches) {
  const box = $("rcptSuggest");
  if (!box) return;

  if (!matches.length) {
    hideSuggest();
    return;
  }

  box.style.display = "";
  box.innerHTML = matches.slice(0, 8).map(u => {
    const keyNote = u.hasKey ? "" : " • (no key yet)";
    return `
      <div class="item" style="padding:8px; cursor:pointer;" data-id="${esc(u.userId)}">
        <div class="itemMain">
          <div class="itemTitle">${esc(u.username)}${keyNote}</div>
          <div class="muted">userId: ${esc(u.userId)}</div>
        </div>
      </div>
    `;
  }).join("");

  box.querySelectorAll("[data-id]").forEach(el => {
    el.addEventListener("click", () => {
      const id = el.getAttribute("data-id");
      const u = orgUsers.find(x => String(x.userId) === String(id));
      if (!u) return;

      // avoid duplicates
      if (!selectedRecipients.some(r => String(r.userId) === String(u.userId))) {
        selectedRecipients.push({ userId: u.userId, username: u.username });
        renderRecipientChips();
      }

      $("rcptInput").value = "";
      hideSuggest();
      $("rcptInput").focus();
    });
  });
}

async function loadOrgRecipients() {
  const resp = await sendBg("QM_RECIPIENTS");
  orgUsers = Array.isArray(resp?.users) ? resp.users : [];
}

function fmtBytes(n) {
  const b = Number(n || 0);
  if (b < 1024) return `${b} B`;
  const kb = b / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(1)} MB`;
  const gb = mb / 1024;
  return `${gb.toFixed(1)} GB`;
}

function updateAttachmentUI() {
  const chips = $("chips");
  chips.innerHTML = "";

  const totalBytes = selectedFiles.reduce((s, f) => s + (f?.size || 0), 0);

  $("attCount").textContent = String(selectedFiles.length);

  if (selectedFiles.length === 0) {
    $("attTitle").textContent = "No files attached";
    $("attHint").textContent = "Click the pin to add one file, then click again to add more.";
    return;
  }

  $("attTitle").textContent = `${selectedFiles.length} file(s) attached`;
  $("attHint").textContent = `Total size: ${fmtBytes(totalBytes)} • Click 📎 to add more.`;

  selectedFiles.forEach((f, idx) => {
    const chip = document.createElement("div");
    chip.className = "chip";

    const name = document.createElement("div");
    name.className = "chipName";
    name.title = `${f.name} (${fmtBytes(f.size)})`;
    name.textContent = `${f.name} • ${fmtBytes(f.size)}`;

    const x = document.createElement("div");
    x.className = "chipX";
    x.textContent = "×";
    x.title = "Remove";
    x.addEventListener("click", () => {
      selectedFiles.splice(idx, 1);
      updateAttachmentUI();
    });

    chip.appendChild(name);
    chip.appendChild(x);
    chips.appendChild(chip);
  });
}

function openPicker() {
  // IMPORTANT: clear input value so selecting the SAME file again still triggers "change"
  const input = $("filePicker");
  input.value = "";
  input.click();
}

function addFilesFromPicker(fileList) {
  const incoming = Array.from(fileList || []);
  if (!incoming.length) return;

  // Append, but dedupe by (name + size + lastModified)
  const key = (f) => `${f.name}::${f.size}::${f.lastModified}`;
  const existing = new Set(selectedFiles.map(key));
  for (const f of incoming) {
    const k = key(f);
    if (!existing.has(k)) {
      selectedFiles.push(f);
      existing.add(k);
    }
  }

  updateAttachmentUI();
}

/* ===== UI helpers ===== */

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
 *
 * ✅ UPDATED: reads from selectedFiles[] (not from <input>)
 */
async function collectAttachmentsImmediate() {
  if (!selectedFiles.length) return [];

  const out = [];
  for (const f of selectedFiles) {
    try {
      const buf = await f.arrayBuffer();
      out.push({
        name: f.name,
        mimeType: f.type || "application/octet-stream",
        size: f.size,
        bytes: Array.from(new Uint8Array(buf))
      });
    } catch (e) {
      throw new Error(
        `Could not read "${f.name}". Try re-selecting it, keep the popup open, and avoid restricted folders. (${e?.name || "ReadError"})`
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
    await loadOrgRecipients();
  } else {
    who.textContent = "Signed out";
    setStatus("Not signed in");
    setDot(null);
  }
}

async function login() {
  ok(""); $("err").textContent = "";
  setStatus("Signing in…");

  //const serverBase = normalizeBase($("serverBase").value.trim());
  const serverBase = DEFAULT_SERVER_BASE;
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
  await loadOrgRecipients();
  renderRecipientChips();
}

async function logout() {
  orgUsers = [];
  selectedRecipients = [];
  hideSuggest();
  renderRecipientChips();
  ok(""); $("err").textContent = "";
  await clearSession();
  ok("Logged out.");
  await refreshSessionUI();
}

async function encryptSelected() {
  ok(""); $("err").textContent = "";
  setStatus("Reading attachments…");

  try {
    const recipientUserIds = selectedRecipients.map(r => r.userId);

    const resp = await sendBg("QM_ENCRYPT_SELECTION", { attachments, recipientUserIds });
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

    const rcptNote = recipientUserIds.length ? `\nRecipients: ${recipientUserIds.length}` : "\nRecipients: (all org users)";
    ok(`Link inserted ✅${attNote}${rcptNote}\nWrapped for ${resp.wrappedCount || "many"} recipient(s).${extra}`);

    // ✅ Clear after encrypt (optional)
    selectedFiles = [];
    updateAttachmentUI();
  } catch (e) {
    console.error(e);
    err(e?.message || String(e));
    setStatus("Error", "bad");
  }
}

async function openHome() {
  const s = await getSession();
  const base = s?.serverBase || normalizeBase($("serverBase").value.trim());
  if (!base) {
    err("Set Server Base first.");
    return;
  }
  chrome.tabs.create({ url: `${base}/portal/index.html` });
}

/* ===== wire up ===== */

$("btnLogin").addEventListener("click", login);
$("btnLogout").addEventListener("click", logout);
$("btnEncrypt").addEventListener("click", encryptSelected);
$("openHome").addEventListener("click", openHome);

$("btnAttach").addEventListener("click", openPicker);
$("filePicker").addEventListener("change", (e) => addFilesFromPicker(e.target.files));

$("rcptInput")?.addEventListener("input", () => {
  const q = String($("rcptInput").value || "").trim().toLowerCase();
  if (!q) return hideSuggest();

  const selectedSet = new Set(selectedRecipients.map(r => String(r.userId)));
  const matches = orgUsers
    .filter(u => !selectedSet.has(String(u.userId)))
    .filter(u => String(u.username || "").toLowerCase().includes(q));

  showSuggest(matches);
});

document.addEventListener("click", (e) => {
  // close suggestions if clicking outside input/suggest
  const box = $("rcptSuggest");
  const input = $("rcptInput");
  if (!box || !input) return;

  if (e.target === input || box.contains(e.target)) return;
  hideSuggest();
});

(async function init() {
  fillDefaults();
  updateAttachmentUI();
  await refreshSessionUI();
})();
