// extension/popup.js
import { normalizeBase, getSession, clearSession } from "./qm.js";

const $ = (id) => document.getElementById(id);
const DEFAULT_SERVER_BASE = "https://quantummail-v2.onrender.com";

/** ===== Attachment state ===== */
let selectedFiles = []; // Array<File>

/** ===== Recipient state ===== */
let orgUsers = []; // [{userId, username, hasKey}]
let selectedRecipients = []; // [{userId, username}]

function esc(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

/* =========================
   UI block toggles
========================= */
function showLogin() {
  $("loginCard")?.classList.remove("hide");
  $("loginCard")?.classList.add("show");
  $("sessionCard")?.classList.remove("show");
  $("sessionCard")?.classList.add("hide");
}

function showSession(user) {
  $("sessionCard")?.classList.remove("hide");
  $("sessionCard")?.classList.add("show");
  $("loginCard")?.classList.remove("show");
  $("loginCard")?.classList.add("hide");

  const line = $("sessionLine");
  if (line) line.textContent = `${user.username}@${user.orgId || "org"} • ${user.role || "Member"}`;
}

/* =========================
   Status helpers
========================= */
function setDot(state) {
  const dot = $("dot");
  if (!dot) return;
  dot.classList.remove("good", "bad");
  if (state === "good") dot.classList.add("good");
  if (state === "bad") dot.classList.add("bad");
}

function setWho(text, state = null) {
  const t = $("whoText");
  if (t) t.textContent = text || "";
  if (state) setDot(state);
  if (!state) setDot(null);
}

function ok(msg) {
  // there are multiple ok/err containers in HTML, so target the ones that exist
  const o = document.querySelectorAll("#ok, #ok_login");
  const e = document.querySelectorAll("#err, #err_login");
  o.forEach((x) => (x.textContent = msg || ""));
  if (msg) e.forEach((x) => (x.textContent = ""));
}

function err(msg) {
  const o = document.querySelectorAll("#ok, #ok_login");
  const e = document.querySelectorAll("#err, #err_login");
  e.forEach((x) => (x.textContent = msg || ""));
  if (msg) o.forEach((x) => (x.textContent = ""));
  setDot("bad");
}

/* =========================
   BG messaging
========================= */
async function sendBg(type, payload = {}) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type, ...payload }, (resp) => resolve(resp));
  });
}

/* =========================
   Recipients UI
========================= */
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
  if (!box) return;
  box.style.display = "none";
  box.innerHTML = "";
}

function showSuggest(matches) {
  const box = $("rcptSuggest");
  if (!box) return;

  if (!matches.length) {
    hideSuggest();
    return;
  }

  box.style.display = "";
  box.innerHTML = matches.slice(0, 8).map((u) => {
    const tag = u.hasKey ? "key ✅" : "no key";
    return `
      <div class="sItem" data-id="${esc(u.userId)}">
        <div>
          <div class="sTitle">${esc(u.username)}</div>
          <div class="sSub">${esc(u.userId)}</div>
        </div>
        <div class="sTag">${tag}</div>
      </div>
    `;
  }).join("");

  box.querySelectorAll("[data-id]").forEach((el) => {
    el.addEventListener("click", () => {
      const id = el.getAttribute("data-id");
      const u = orgUsers.find((x) => String(x.userId) === String(id));
      if (!u) return;

      if (!selectedRecipients.some((r) => String(r.userId) === String(u.userId))) {
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

/* =========================
   Attachments UI
========================= */
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
  if (!chips) return;
  chips.innerHTML = "";

  const totalBytes = selectedFiles.reduce((s, f) => s + (f?.size || 0), 0);

  if ($("attCount")) $("attCount").textContent = String(selectedFiles.length);

  if (selectedFiles.length === 0) {
    if ($("attTitle")) $("attTitle").textContent = "No files attached";
    if ($("attHint")) $("attHint").textContent = "Click 📎 to add files (up to 8MB total).";
    return;
  }

  if ($("attTitle")) $("attTitle").textContent = `${selectedFiles.length} file(s) attached`;
  if ($("attHint")) $("attHint").textContent = `Total size: ${fmtBytes(totalBytes)} • Click 📎 to add more.`;

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
  const input = $("filePicker");
  if (!input) return;
  input.value = ""; // allow selecting same file again
  input.click();
}

function addFilesFromPicker(fileList) {
  const incoming = Array.from(fileList || []);
  if (!incoming.length) return;

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

/**
 * IMPORTANT:
 * Read attachments immediately (before any other awaits),
 * otherwise MV3 popup can lose file handle and throw NotReadableError.
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
        `Could not read "${f.name}". Try re-selecting it and keep popup open. (${e?.name || "ReadError"})`
      );
    }
  }
  return out;
}

/* =========================
   Session UI
========================= */
function fillDefaults() {
  if ($("orgId") && !$("orgId").value) $("orgId").value = "org_demo";
}

async function refreshSessionUI() {
  const s = await getSession();

  if (s?.token && s?.user) {
    setWho(`${s.user.username}@${s.user.orgId || "org"}`, "good");
    showSession(s.user);

    if ($("serverBase") && !$("serverBase").value && s.serverBase) $("serverBase").value = s.serverBase;
    if ($("orgId") && !$("orgId").value && s.user.orgId) $("orgId").value = s.user.orgId;
    if ($("username") && !$("username").value) $("username").value = s.user.username || "";

    await loadOrgRecipients();
  } else {
    setWho("Signed out");
    showLogin();
    orgUsers = [];
  }
}

/* =========================
   Actions
========================= */
async function login() {
  ok(""); err("");
  setWho("Signing in…", null);

  const serverBase = DEFAULT_SERVER_BASE;
  const orgId = $("orgId")?.value.trim() || "";
  const username = $("username")?.value.trim() || "";
  const password = $("password")?.value || "";

  if (!serverBase || !orgId || !username || !password) {
    err("orgId, username, and password are required.");
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

async function logoutAll() {
  orgUsers = [];
  selectedRecipients = [];
  hideSuggest();
  renderRecipientChips();

  selectedFiles = [];
  updateAttachmentUI();

  ok(""); err("");
  await clearSession();
  ok("Logged out.");
  await refreshSessionUI();
}

async function clearLoginFields() {
  if ($("username")) $("username").value = "";
  if ($("password")) $("password").value = "";
  if ($("orgId")) $("orgId").value = "org_demo";
  ok(""); err("");
}

async function encryptSelected() {
  ok(""); err("");
  setWho("Working…", null);

  try {
    // ✅ MUST be first (MV3 file handles)
    const attachments = await collectAttachmentsImmediate();

    const s = await getSession();
    if (!s?.token) {
      err("Please login first.");
      setWho("Signed out");
      return;
    }

    const recipientUserIds = selectedRecipients.map((r) => r.userId);
    const resp = await sendBg("QM_ENCRYPT_SELECTION", { attachments, recipientUserIds });

    if (!resp?.ok) {
      err(resp?.error || "Encrypt failed");
      return;
    }

    const extra =
      (typeof resp.skippedNoKey === "number" && resp.skippedNoKey > 0)
        ? `\nSkipped ${resp.skippedNoKey} (no key yet).`
        : "";

    const attNote = attachments.length ? `\nAttachments: ${attachments.length}` : "";
    const rcptNote = recipientUserIds.length
      ? `\nRecipients: ${recipientUserIds.length}`
      : `\nRecipients: all org users`;

    ok(`Link inserted ✅${attNote}${rcptNote}\nWrapped for ${resp.wrappedCount || "many"} recipient(s).${extra}`);
    setWho(`${s.user.username}@${s.user.orgId || "org"}`, "good");

    // optional cleanup
    selectedFiles = [];
    updateAttachmentUI();
  } catch (e) {
    console.error(e);
    err(e?.message || String(e));
  }
}

async function openHome() {
  const s = await getSession();
  const base = s?.serverBase || normalizeBase(($("serverBase")?.value || "").trim());
  if (!base) {
    err("Server base missing.");
    return;
  }
  chrome.tabs.create({ url: `${base}/portal/index.html` });
}

/* =========================
   Wiring
========================= */
$("btnLogin")?.addEventListener("click", login);
$("btnLogout")?.addEventListener("click", clearLoginFields);
$("btnLogoutTop")?.addEventListener("click", logoutAll);

$("btnEncrypt")?.addEventListener("click", encryptSelected);
$("openHome")?.addEventListener("click", openHome);

$("btnAttach")?.addEventListener("click", openPicker);
$("filePicker")?.addEventListener("change", (e) => addFilesFromPicker(e.target.files));

$("rcptInput")?.addEventListener("input", () => {
  const q = String($("rcptInput").value || "").trim().toLowerCase();
  if (!q) return hideSuggest();

  const selectedSet = new Set(selectedRecipients.map((r) => String(r.userId)));
  const matches = orgUsers
    .filter((u) => !selectedSet.has(String(u.userId)))
    .filter((u) => String(u.username || "").toLowerCase().includes(q));

  showSuggest(matches);
});

document.addEventListener("click", (e) => {
  const box = $("rcptSuggest");
  const input = $("rcptInput");
  if (!box || !input) return;

  if (e.target === input || box.contains(e.target)) return;
  hideSuggest();
});

(async function init() {
  fillDefaults();
  updateAttachmentUI();
  renderRecipientChips();
  await refreshSessionUI();
})();
