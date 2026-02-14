const $ = (id) => document.getElementById(id);

let token = "";
let sessionUser = null;

function setText(id, msg) {
  const el = $(id);
  if (el) el.textContent = msg || "";
}
function ok(id, msg) { setText(id, msg); }
function err(id, msg) { setText(id, msg); }

function setSessionPill() {
  const who = $("who");
  const dot = $("sessionDot");

  if (who) {
    who.textContent = token && sessionUser
      ? `${sessionUser.username}@${sessionUser.orgId} (${sessionUser.role})`
      : "Not logged in";
  }
  if (dot) {
    dot.classList.remove("good", "bad");
    if (token) dot.classList.add("good");
  }
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
function daysOld(iso) {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((Date.now() - t) / (24 * 60 * 60 * 1000));
}

async function createAdmin() {
  ok("seedOk", ""); err("seedErr", "");
  const orgId = String($("seedOrgId")?.value || "").trim();
  const username = String($("seedUsername")?.value || "").trim();
  const password = String($("seedPassword")?.value || "");
  if (!orgId || !username || !password) {
    err("seedErr", "Org Id, Admin Username, and Admin Password are required.");
    return;
  }
  const out = await api("/dev/seed-admin", { method: "POST", body: { orgId, username, password } });
  ok("seedOk", `Admin created ✅\nOrg: ${out.orgId}\nUsername: ${username}`);
}

async function login() {
  ok("authOk", ""); err("authErr", "");
  const orgId = String($("orgId")?.value || "").trim();
  const username = String($("username")?.value || "").trim();
  const password = String($("password")?.value || "");
  if (!orgId || !username || !password) {
    err("authErr", "Org Id, Username, and Password are required.");
    return;
  }

  const out = await api("/auth/login", { method: "POST", body: { orgId, username, password } });
  token = out.token;
  sessionUser = out.user;
  ok("authOk", "Logged in ✅");
  setSessionPill();

  await refreshUsers();
  await refreshAlertsBadge();
}

function logout() {
  token = "";
  sessionUser = null;
  ok("authOk", "Logged out."); err("authErr", "");
  setSessionPill();
  const tbody = $("usersTbody");
  if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="muted">Login to load users…</td></tr>`;
  const badge = $("alertBadge");
  if (badge) badge.style.display = "none";
}

function escapeHtml(s) {
  return String(s || "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}
function escapeAttr(s) { return escapeHtml(s).replaceAll("`", "&#096;"); }

function renderUsers(users) {
  const tbody = $("usersTbody");
  if (!tbody) return;

  if (!Array.isArray(users) || users.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="muted">No users found.</td></tr>`;
    return;
  }

  tbody.innerHTML = users.map((u) => {
    const keyAge = u.publicKeyRegisteredAt ? daysOld(u.publicKeyRegisteredAt) : null;
    const keyHealth = u.hasPublicKey
      ? `✅ Registered${keyAge != null ? ` • ${keyAge}d` : ""}`
      : `— None`;

    return `
      <tr>
        <td><b>${escapeHtml(u.username || "")}</b><br/><span class="muted">${escapeHtml(u.userId || "")}</span></td>
        <td>${escapeHtml(u.role || "Member")}</td>
        <td>${escapeHtml(u.status || "Active")}</td>
        <td>${escapeHtml(keyHealth)}</td>
        <td>${escapeHtml(fmtIso(u.lastLoginAt))}</td>
        <td>
          <button data-action="clearKey" data-userid="${escapeAttr(u.userId)}" class="secondary">Force Re-key</button>
          <button data-action="removeUser" data-userid="${escapeAttr(u.userId)}" class="danger">Remove</button>
        </td>
      </tr>
    `;
  }).join("");

  tbody.querySelectorAll("button[data-action]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const action = btn.getAttribute("data-action");
      const userId = btn.getAttribute("data-userid");
      if (!action || !userId) return;

      try {
        ok("usersOk", ""); err("usersErr", "");
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
  ok("usersOk", ""); err("usersErr", "");
  if (!token) { err("usersErr", "Login required to load users."); return; }
  const out = await api("/admin/users");
  renderUsers(out.users || []);
}

async function createUser() {
  ok("usersOk", ""); err("usersErr", "");
  if (!token) { err("usersErr", "Login required."); return; }

  const username = String($("newUsername")?.value || "").trim();
  const password = String($("newPassword")?.value || "");
  const role = String($("newRole")?.value || "Member").trim() || "Member";
  if (!username || !password) { err("usersErr", "New Username and New Password are required."); return; }

  await api("/admin/users", { method: "POST", body: { username, password, role } });
  ok("usersOk", `User created ✅ (${username})`);
  $("newUsername").value = ""; $("newPassword").value = "";
  await refreshUsers();
}

async function refreshAlertsBadge() {
  const badge = $("alertBadge");
  if (!badge) return;
  if (!token) { badge.style.display = "none"; return; }

  try {
    const out = await api("/admin/alerts?minutes=60");
    const count = Array.isArray(out.alerts) ? out.alerts.length : 0;
    if (count > 0) {
      badge.textContent = String(count);
      badge.style.display = "";
    } else {
      badge.style.display = "none";
    }
  } catch {
    badge.style.display = "none";
  }
}

// Wire up
$("btnCreateAdmin")?.addEventListener("click", () => createAdmin().catch(e => err("seedErr", e.message)));
$("btnLogin")?.addEventListener("click", () => login().catch(e => err("authErr", e.message)));
$("btnLogout")?.addEventListener("click", logout);
$("btnCreateUser")?.addEventListener("click", () => createUser().catch(e => err("usersErr", e.message)));
$("btnRefreshUsers")?.addEventListener("click", () => refreshUsers().catch(e => err("usersErr", e.message)));

setSessionPill();
