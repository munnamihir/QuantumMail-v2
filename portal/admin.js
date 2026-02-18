const $ = (id) => document.getElementById(id);

let token = "";
let sessionUser = null;

function debounce(fn, ms = 400) {
  let t = null;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function setFieldState(inputId, msgId, state, msg) {
  const input = $(inputId);
  const msgEl = $(msgId);
  if (msgEl) msgEl.textContent = msg || "";

  if (input) {
    input.classList.remove("goodField", "badField");
    if (state === "good") input.classList.add("goodField");
    if (state === "bad") input.classList.add("badField");
  }
}

async function apiPublic(path) {
  const res = await fetch(path);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}


function setText(id, msg) {
  const el = $(id);
  if (el) el.textContent = msg || "";
}
function ok(id, msg) { setText(id, msg); }
function err(id, msg) { setText(id, msg); }

function openProfile() {
  const modal = $("profileModal");
  if (!modal) return;

  // Update meta
  const meta = $("profileMeta");
  if (meta) {
    meta.textContent = token && sessionUser
      ? `${sessionUser.username}@${sessionUser.orgId} • ${sessionUser.role}`
      : "Not logged in.";
  }

  // Clear messages/inputs
  ok("pwOk", ""); err("pwErr", "");
  if ($("curPw")) $("curPw").value = "";
  if ($("newPw")) $("newPw").value = "";
  if ($("newPw2")) $("newPw2").value = "";

  modal.style.display = "";
}

function closeProfile() {
  const modal = $("profileModal");
  if (modal) modal.style.display = "none";
}


function setSessionPill() {
  const who = $("who");
  const dot = $("sessionDot");
  const btn = $("btnProfile");

  if (who) {
    who.textContent = token && sessionUser
      ? `${sessionUser.username}@${sessionUser.orgId} (${sessionUser.role})`
      : "Not logged in";
  }
  if (dot) {
    dot.classList.remove("good", "bad");
    if (token) dot.classList.add("good");
  }
  if (btn) btn.disabled = !token;
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
  sessionStorage.setItem("qm_admin_token", token);
  sessionUser = out.user;
  ok("authOk", "Logged in ✅");
  setSessionPill();

  await refreshUsers();
  await refreshAlertsBadge();
}

function logout() {
  token = "";
  sessionUser = null;
  sessionStorage.removeItem("qm_admin_token");
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

async function checkOrgInitialization() {
  const urlParams = new URLSearchParams(window.location.search);
  const orgIdFromQuery = urlParams.get("orgId");
  if (orgIdFromQuery) {
    $("seedOrgId").value = orgIdFromQuery;
    $("orgId").value = orgIdFromQuery;
  }
}


async function changeMyPassword() {
  ok("pwOk", ""); err("pwErr", "");
  if (!token) { err("pwErr", "Login required."); return; }

  const currentPassword = String($("curPw")?.value || "");
  const newPassword = String($("newPw")?.value || "");
  const confirm = String($("newPw2")?.value || "");

  if (!currentPassword || !newPassword) {
    err("pwErr", "Current and new password are required.");
    return;
  }
  if (newPassword.length < 8) {
    err("pwErr", "New password must be at least 8 characters.");
    return;
  }
  if (newPassword !== confirm) {
    err("pwErr", "New password and confirmation do not match.");
    return;
  }

  await api("/auth/change-password", {
    method: "POST",
    body: { currentPassword, newPassword }
  });

  ok("pwOk", "Password updated ✅");
  $("curPw").value = ""; $("newPw").value = ""; $("newPw2").value = "";
}

const checkSeedOrgLive = debounce(async () => {
  const orgId = String($("seedOrgId")?.value || "").trim();
  if (!orgId) { setFieldState("seedOrgId", "seedOrgStatus", null, ""); return; }

  try {
    const out = await apiPublic(`/org/check?orgId=${encodeURIComponent(orgId)}`);

    if (!out.exists) {
      setFieldState("seedOrgId", "seedOrgStatus", "good", "Org ID is available ✅ (will be created on Admin seed)");
    } else if (out.initialized) {
      setFieldState("seedOrgId", "seedOrgStatus", "bad", `Org already initialized ✅ Users: ${out.userCount}. Use Login instead.`);
    } else {
      setFieldState("seedOrgId", "seedOrgStatus", "bad", "Org exists but not initialized. You can still seed admin, but consider cleaning data.json.");
    }
  } catch (e) {
    setFieldState("seedOrgId", "seedOrgStatus", "bad", e.message || "Org check failed");
  }
}, 450);

const checkLoginOrgLive = debounce(async () => {
  const orgId = String($("orgId")?.value || "").trim();
  if (!orgId) { setFieldState("orgId", "loginOrgStatus", null, ""); return; }

  try {
    const out = await apiPublic(`/org/check?orgId=${encodeURIComponent(orgId)}`);

    if (!out.exists) {
      setFieldState("orgId", "loginOrgStatus", "bad", "Org not found.");
    } else if (!out.initialized) {
      setFieldState("orgId", "loginOrgStatus", "bad", "Org not initialized yet. Seed an Admin first.");
    } else {
      setFieldState("orgId", "loginOrgStatus", "good", `Org found ✅ Users: ${out.userCount}`);
    }
  } catch (e) {
    setFieldState("orgId", "loginOrgStatus", "bad", e.message || "Org check failed");
  }
}, 450);

const checkSeedUsernameLive = debounce(async () => {
  const orgId = String($("seedOrgId")?.value || "").trim();
  const username = String($("seedUsername")?.value || "").trim();
  if (!orgId || !username) { setFieldState("seedUsername", "seedUserStatus", null, ""); return; }

  try {
    const org = await apiPublic(`/org/check?orgId=${encodeURIComponent(orgId)}`);
    // If org doesn't exist yet, username is fine (no users)
    if (!org.exists) {
      setFieldState("seedUsername", "seedUserStatus", "good", "Username looks good ✅ (org not created yet)");
      return;
    }

    const out = await apiPublic(`/org/check-username?orgId=${encodeURIComponent(orgId)}&username=${encodeURIComponent(username)}`);
    if (out.available) setFieldState("seedUsername", "seedUserStatus", "good", "Username is available ✅");
    else setFieldState("seedUsername", "seedUserStatus", "bad", "Username already exists in this org.");
  } catch (e) {
    setFieldState("seedUsername", "seedUserStatus", "bad", e.message || "Username check failed");
  }
}, 450);

const checkLoginUsernameLive = debounce(async () => {
  const orgId = String($("orgId")?.value || "").trim();
  const username = String($("username")?.value || "").trim();
  if (!orgId || !username) { setFieldState("username", "loginUserStatus", null, ""); return; }

  try {
    const out = await apiPublic(`/org/check-username?orgId=${encodeURIComponent(orgId)}&username=${encodeURIComponent(username)}`);
    if (!out.orgExists) {
      setFieldState("username", "loginUserStatus", "bad", "Org not found.");
      return;
    }
    // For login: if not available => it means taken => good sign (account exists)
    if (!out.available) setFieldState("username", "loginUserStatus", "good", "User found ✅");
    else setFieldState("username", "loginUserStatus", "bad", "User not found in this org.");
  } catch (e) {
    setFieldState("username", "loginUserStatus", "bad", e.message || "User check failed");
  }
}, 450);

const checkNewUserUsernameLive = debounce(async () => {
  const orgId = String($("orgId")?.value || "").trim(); // admin login org field
  const username = String($("newUsername")?.value || "").trim();
  if (!orgId || !username) { setFieldState("newUsername", "newUserStatus", null, ""); return; }

  try {
    const out = await apiPublic(`/org/check-username?orgId=${encodeURIComponent(orgId)}&username=${encodeURIComponent(username)}`);
    if (!out.orgExists) {
      setFieldState("newUsername", "newUserStatus", "bad", "Org not found.");
      return;
    }
    if (out.available) setFieldState("newUsername", "newUserStatus", "good", "Username is available ✅");
    else setFieldState("newUsername", "newUserStatus", "bad", "Username already taken.");
  } catch (e) {
    setFieldState("newUsername", "newUserStatus", "bad", e.message || "Username check failed");
  }
}, 450);


// Wire up
$("btnCreateAdmin")?.addEventListener("click", () => createAdmin().catch(e => err("seedErr", e.message)));
$("btnLogin")?.addEventListener("click", () => login().catch(e => err("authErr", e.message)));
$("btnLogout")?.addEventListener("click", logout);
$("btnCreateUser")?.addEventListener("click", () => createUser().catch(e => err("usersErr", e.message)));
$("btnRefreshUsers")?.addEventListener("click", () => refreshUsers().catch(e => err("usersErr", e.message)));
$("profileModal")?.addEventListener("click", (e) => {
  if (e.target && e.target.id === "profileModal") closeProfile();
});
$("btnProfile")?.addEventListener("click", () => openProfile());
$("btnCloseProfile")?.addEventListener("click", closeProfile);
$("btnChangePw")?.addEventListener("click", () => changeMyPassword().catch(e => err("pwErr", e.message)));

$("btnLogoutProfile")?.addEventListener("click", () => {
  closeProfile();
  logout();
});
// Live checks
$("seedOrgId")?.addEventListener("input", () => { checkSeedOrgLive(); checkSeedUsernameLive(); });
$("seedUsername")?.addEventListener("input", () => checkSeedUsernameLive());

$("orgId")?.addEventListener("input", () => { checkLoginOrgLive(); checkLoginUsernameLive(); });
$("username")?.addEventListener("input", () => checkLoginUsernameLive());

$("newUsername")?.addEventListener("input", () => checkNewUserUsernameLive());

checkSeedOrgLive();
checkLoginOrgLive();
checkOrgInitialization();
setSessionPill();
