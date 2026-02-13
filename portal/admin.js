// portal/admin.js
const API = window.location.origin;
const $ = (id) => document.getElementById(id);

function setStatus(msg) { $("status").textContent = msg || ""; }
function setError(msg) { $("error").textContent = msg || ""; }

function saveSession(session) {
  localStorage.setItem("qm_admin_session", JSON.stringify(session));
}
function loadSession() {
  try { return JSON.parse(localStorage.getItem("qm_admin_session") || "null"); }
  catch { return null; }
}
function clearSession() { localStorage.removeItem("qm_admin_session"); }

async function apiFetch(path, { method = "GET", token = null, json = null } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (json) headers["Content-Type"] = "application/json";

  const res = await fetch(`${API}${path}`, {
    method,
    headers,
    body: json ? JSON.stringify(json) : undefined
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function updatePills() {
  const session = loadSession();
  $("orgPill").textContent = session?.user?.orgId || $("orgId")?.value || "-";
  $("sessionPill").textContent = session?.token ? `signed in as ${session.user.username}` : "signed out";
}

function renderUsers(users) {
  const tb = $("usersTable")?.querySelector("tbody");
  tb.innerHTML = "";

  for (const u of users) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(u.userId)}</td>
      <td>${escapeHtml(u.username)}</td>
      <td>${escapeHtml(u.role)}</td>
      <td>${escapeHtml(u.status || "Active")}</td>
      <td>${u.hasPublicKey ? "✅" : "❌"}</td>
    `;
    tb.appendChild(tr);
  }
}

let LAST_AUDIT = [];

function renderAudit(items) {
  LAST_AUDIT = Array.isArray(items) ? items : [];
  const tb = $("auditTable")?.querySelector("tbody");
  tb.innerHTML = "";

  for (const a of LAST_AUDIT) {
    const details = { ...a };
    delete details.id;
    delete details.orgId;
    delete details.userId;
    delete details.action;
    delete details.ip;
    delete details.ua;
    delete details.at;

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(a.at)}</td>
      <td>${escapeHtml(a.action)}</td>
      <td>${escapeHtml(a.userId || "")}</td>
      <td><code>${escapeHtml(JSON.stringify(details))}</code></td>
      <td>${escapeHtml(a.ip || "")}</td>
    `;
    tb.appendChild(tr);
  }
}

function renderKeys(active, keys) {
  const tb = $("keysTable")?.querySelector("tbody");
  tb.innerHTML = "";

  for (const k of keys) {
    const isActive = String(k.version) === String(active);
    const canRetire = !isActive && k.status !== "retired";

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(k.version)}${isActive ? " ✅" : ""}</td>
      <td>${escapeHtml(k.status)}</td>
      <td>${escapeHtml(k.createdAt || "")}</td>
      <td>${escapeHtml(k.activatedAt || "")}</td>
      <td>${escapeHtml(k.retiredAt || "")}</td>
      <td>
        <button data-retire="${escapeHtml(k.version)}" ${canRetire ? "" : "disabled"}>Retire</button>
      </td>
    `;
    tb.appendChild(tr);
  }

  tb.querySelectorAll("button[data-retire]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const v = btn.getAttribute("data-retire");
      try {
        await retireKey(v);
      } catch (e) {
        setError(e.message || String(e));
      }
    });
  });
}

async function seedAdmin() {
  setError("");
  setStatus("Seeding admin…");
  const orgId = ($("orgId").value || "org_demo").trim();
  const r = await apiFetch("/dev/seed-admin", { method: "POST", json: { orgId } });
  setStatus(`Seeded ✅ Admin: ${r.admin} / ${r.password}`);
  updatePills();
}

async function loginAdmin() {
  setError("");
  setStatus("Logging in…");

  const orgId = ($("orgId").value || "").trim();
  const username = ($("username").value || "").trim();
  const password = ($("password").value || "");

  if (!orgId || !username || !password) throw new Error("orgId, username, password required");

  const data = await apiFetch("/auth/login", { method: "POST", json: { orgId, username, password } });
  if (data?.user?.role !== "Admin") throw new Error("Not an admin user");

  saveSession({ token: data.token, user: data.user });
  setStatus("Logged in ✅");
  updatePills();

  await refreshAll();
}

async function refreshAll() {
  setError("");
  const session = loadSession();
  if (!session?.token) throw new Error("Not logged in");

  setStatus("Loading users + keys + audit…");
  updatePills();

  const [usersRes, keysRes, auditRes] = await Promise.all([
    apiFetch("/admin/users", { token: session.token }),
    apiFetch("/admin/keys", { token: session.token }),
    apiFetch("/admin/audit?limit=300", { token: session.token })
  ]);

  renderUsers(usersRes.users || []);
  renderKeys(keysRes.active, keysRes.keys || []);
  renderAudit(auditRes.items || []);

  setStatus("Updated ✅");
}

async function createMember() {
  setError("");
  const session = loadSession();
  if (!session?.token) throw new Error("Not logged in");

  const username = ($("newUsername").value || "").trim();
  const password = ($("newPassword").value || "");
  const role = ($("newRole").value || "Member").trim();

  if (!username || !password) throw new Error("New username/password required");

  setStatus("Creating user…");
  await apiFetch("/admin/users", {
    method: "POST",
    token: session.token,
    json: { username, password, role }
  });

  $("newUsername").value = "";
  $("newPassword").value = "";
  $("newRole").value = "Member";

  setStatus("User created ✅");
  await refreshAll();
}

async function rotateKey() {
  setError("");
  const session = loadSession();
  if (!session?.token) throw new Error("Not logged in");

  setStatus("Rotating key…");
  await apiFetch("/admin/keys/rotate", { method: "POST", token: session.token });
  setStatus("Key rotated ✅");
  await refreshAll();
}

async function retireKey(version) {
  setError("");
  const session = loadSession();
  if (!session?.token) throw new Error("Not logged in");

  setStatus(`Retiring key v${version}…`);
  await apiFetch(`/admin/keys/${version}/retire`, { method: "POST", token: session.token });
  setStatus(`Key v${version} retired ✅`);
  await refreshAll();
}

function logout() {
  clearSession();
  updatePills();
  setStatus("Logged out.");
  setError("");
  renderUsers([]);
  renderKeys("-", []);
  renderAudit([]);
}

function downloadAuditCsv() {
  const headers = ["at", "action", "userId", "ip", "details"];
  const rows = [headers];

  for (const a of LAST_AUDIT) {
    const json = JSON.stringify(a);
    const row = [
      a.at || "",
      a.action || "",
      a.userId || "",
      a.ip || "",
      json
    ].map((v) => `"${String(v).replaceAll('"', '""')}"`);

    rows.push(row);
  }

  const csv = rows.map((r) => r.join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = `quantummail-audit-${new Date().toISOString().slice(0,19).replaceAll(":","-")}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();

  URL.revokeObjectURL(url);
}

document.addEventListener("DOMContentLoaded", () => {
  updatePills();

  $("btnSeed").addEventListener("click", () => seedAdmin().catch((e) => setError(e.message || String(e))));
  $("btnLogin").addEventListener("click", () => loginAdmin().catch((e) => setError(e.message || String(e))));
  $("btnRefresh").addEventListener("click", () => refreshAll().catch((e) => setError(e.message || String(e))));
  $("btnCreateUser").addEventListener("click", () => createMember().catch((e) => setError(e.message || String(e))));
  $("btnRotateKey").addEventListener("click", () => rotateKey().catch((e) => setError(e.message || String(e))));
  $("btnLogout").addEventListener("click", logout);
  $("btnDownloadLog").addEventListener("click", downloadAuditCsv);

  const session = loadSession();
  if (session?.token) refreshAll().catch(() => {});
});
