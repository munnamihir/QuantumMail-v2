const $ = (id) => document.getElementById(id);

let token = "";
let sessionUser = null;

function ok(id, msg) { const el = $(id); if (el) el.textContent = msg || ""; }
function err(id, msg) { const el = $(id); if (el) el.textContent = msg || ""; }

function debounce(fn, ms = 350) {
  let t = null;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

async function apiPublic(path) {
  const res = await fetch(path);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

async function api(path, { method = "GET", body = null } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers["Content-Type"] = "application/json";

  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

function fmtIso(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

const checkOrgLive = debounce(async () => {
  const orgId = String($("orgId").value || "").trim();
  if (!orgId) { $("orgStatus").textContent = ""; return; }
  try {
    const out = await apiPublic(`/org/check?orgId=${encodeURIComponent(orgId)}`);
    if (!out.exists) $("orgStatus").textContent = "Org not found.";
    else if (!out.initialized) $("orgStatus").textContent = "Org not initialized yet.";
    else $("orgStatus").textContent = `Org ready ✅ Users: ${out.userCount}`;
  } catch (e) {
    $("orgStatus").textContent = e.message || "Org check failed";
  }
}, 400);

const checkNewUserLive = debounce(async () => {
  const orgId = String($("orgId").value || "").trim();
  const username = String($("newUsername").value || "").trim();
  if (!orgId || !username) { $("newUserStatus").textContent = ""; return; }

  try {
    const out = await apiPublic(`/org/check-username?orgId=${encodeURIComponent(orgId)}&username=${encodeURIComponent(username)}`);
    if (!out.orgExists) { $("newUserStatus").textContent = "Org not found."; return; }
    $("newUserStatus").textContent = out.available ? "Username available ✅" : "Username taken.";
  } catch (e) {
    $("newUserStatus").textContent = e.message || "Username check failed";
  }
}, 400);

async function login() {
  ok("authOk",""); err("authErr","");
  const orgId = String($("orgId").value || "").trim();
  const username = String($("username").value || "").trim();
  const password = String($("password").value || "");

  if (!orgId || !username || !password) { err("authErr","Org ID, username, password required."); return; }

  const out = await api("/auth/login", { method:"POST", body:{ orgId, username, password } });
  token = out.token;
  sessionUser = out.user;

  sessionStorage.setItem("qm_admin_token", token);
  sessionStorage.setItem("qm_user", JSON.stringify(out.user));

  if (out.user?.role === "SuperAdmin") {
    window.location.href = "/portal/.qm/super.html";
    return;
  }
  if (out.user?.role !== "Admin") {
    err("authErr", "This page is Admin-only. Use Inbox for Member accounts.");
    return;
  }

  ok("authOk","Logged in ✅");
  await refreshUsers();
}

function logout() {
  token = "";
  sessionUser = null;
  sessionStorage.removeItem("qm_admin_token");
  ok("authOk","Logged out.");
  err("authErr","");
  $("usersTbody").innerHTML = `<tr><td colspan="6" class="muted">Login to load users…</td></tr>`;
}

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;")
    .replaceAll('"',"&quot;").replaceAll("'","&#039;");
}

function renderUsers(users) {
  const tbody = $("usersTbody");
  if (!tbody) return;

  if (!Array.isArray(users) || users.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="muted">No users found.</td></tr>`;
    return;
  }

  tbody.innerHTML = users.map(u => `
    <tr>
      <td><b>${escapeHtml(u.username)}</b><br/><span class="muted">${escapeHtml(u.userId)}</span></td>
      <td>${escapeHtml(u.role || "Member")}</td>
      <td>${escapeHtml(u.status || "Active")}</td>
      <td>${u.hasPublicKey ? "✅ Registered" : "— None"}</td>
      <td>${escapeHtml(fmtIso(u.lastLoginAt))}</td>
      <td>
        <button data-action="clearKey" data-userid="${escapeHtml(u.userId)}" class="secondary" type="button">Force Re-key</button>
        <button data-action="removeUser" data-userid="${escapeHtml(u.userId)}" class="danger" type="button">Remove</button>
      </td>
    </tr>
  `).join("");

  tbody.querySelectorAll("button[data-action]").forEach(btn => {
    btn.addEventListener("click", async () => {
      ok("usersOk",""); err("usersErr","");
      try {
        const action = btn.getAttribute("data-action");
        const userId = btn.getAttribute("data-userid");
        if (!token) throw new Error("Login required.");

        if (action === "removeUser") {
          await api(`/admin/users/${encodeURIComponent(userId)}`, { method: "DELETE" });
          ok("usersOk", "User removed ✅");
        }
        if (action === "clearKey") {
          await api(`/admin/users/${encodeURIComponent(userId)}/clear-key`, { method: "POST" });
          ok("usersOk", "Public key cleared ✅");
        }

        await refreshUsers();
      } catch (e) {
        err("usersErr", e?.message || String(e));
      }
    });
  });
}

async function refreshUsers() {
  ok("usersOk",""); err("usersErr","");
  if (!token) { err("usersErr","Login required."); return; }
  const out = await api("/admin/users");
  renderUsers(out.users || []);
}

async function createUser() {
  ok("usersOk",""); err("usersErr","");
  if (!token) { err("usersErr","Login required."); return; }

  const orgId = String($("orgId").value || "").trim();
  const username = String($("newUsername").value || "").trim();
  const password = String($("newPassword").value || "");
  const role = String($("newRole").value || "Member");

  if (!orgId) { err("usersErr","Missing orgId."); return; }
  if (!username || !password) { err("usersErr","New username and password required."); return; }

  const chk = await apiPublic(`/org/check-username?orgId=${encodeURIComponent(orgId)}&username=${encodeURIComponent(username)}`);
  if (!chk.orgExists) { err("usersErr","Org not found."); return; }
  if (!chk.available) { err("usersErr","Username already taken."); return; }

  await api("/admin/users", { method:"POST", body:{ username, password, role } });
  ok("usersOk", `User created ✅ (${username})`);

  $("newUsername").value = "";
  $("newPassword").value = "";
  $("newUserStatus").textContent = "";
  await refreshUsers();
}

/* Boot: try restore session */
(function boot() {
  const saved = sessionStorage.getItem("qm_admin_token");
  if (saved) token = saved;

  $("btnLogin").addEventListener("click", () => login().catch(e => err("authErr", e.message)));
  $("btnLogout").addEventListener("click", logout);
  $("btnCreateUser").addEventListener("click", () => createUser().catch(e => err("usersErr", e.message)));
  $("btnRefreshUsers").addEventListener("click", () => refreshUsers().catch(e => err("usersErr", e.message)));

  $("orgId")?.addEventListener("input", () => checkOrgLive());
  $("newUsername")?.addEventListener("input", () => checkNewUserLive());

  checkOrgLive();

  // If we already have token, fetch /auth/me to confirm role quickly
  if (token) {
    api("/auth/me").then(out => {
      sessionUser = out.user;
      if (out.user?.role === "SuperAdmin") window.location.href = "/portal/.qm/super.html";
      if (out.user?.role === "Admin") refreshUsers();
    }).catch(() => {});
  }
})();
