const $ = (id) => document.getElementById(id);

function ok(id, msg) { const el = $(id); if (el) el.textContent = msg || ""; }
function err(id, msg) { const el = $(id); if (el) el.textContent = msg || ""; }

function debounce(fn, ms = 350) {
  let t = null;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

function clearAllMsgs() {
  ["rqOk","rqErr","jnOk","jnErr","liOk","liErr"].forEach(x => { ok(x,""); err(x,""); });
}

function setTab(which) {
  const isReq = which === "request";
  const isJoin = which === "join";
  const isLogin = which === "login";

  $("tabRequest").classList.toggle("active", isReq);
  $("tabJoin").classList.toggle("active", isJoin);
  $("tabLogin").classList.toggle("active", isLogin);

  $("requestPanel").style.display = isReq ? "" : "none";
  $("joinPanel").style.display = isJoin ? "" : "none";
  $("loginPanel").style.display = isLogin ? "" : "none";

  clearAllMsgs();
}

async function apiPublic(path) {
  const res = await fetch(path);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

async function api(path, { method = "GET", body = null, token = "" } = {}) {
  const headers = {};
  if (body) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

/* -----------------------------
   Live checks (Join + Login)
------------------------------ */
const checkJoinOrgLive = debounce(async () => {
  const orgId = String($("jnOrgId").value || "").trim();
  if (!orgId) { $("jnOrgStatus").textContent = ""; return; }

  try {
    const out = await apiPublic(`/org/check?orgId=${encodeURIComponent(orgId)}`);
    if (!out.exists) {
      $("jnOrgStatus").textContent = "Org not found. Submit a request on the first tab.";
    } else if (!out.initialized) {
      $("jnOrgStatus").textContent = "Org exists but not initialized yet. Admin must finish setup first.";
    } else {
      $("jnOrgStatus").textContent = `Org ready ✅ Users: ${out.userCount}`;
    }
  } catch (e) {
    $("jnOrgStatus").textContent = e.message || "Org check failed";
  }
}, 400);

const checkJoinUsernameLive = debounce(async () => {
  const orgId = String($("jnOrgId").value || "").trim();
  const username = String($("jnUsername").value || "").trim();
  if (!orgId || !username) { $("jnUserStatus").textContent = ""; return; }

  try {
    const org = await apiPublic(`/org/check?orgId=${encodeURIComponent(orgId)}`);
    if (!org.exists) { $("jnUserStatus").textContent = "Org not found."; return; }
    if (!org.initialized) { $("jnUserStatus").textContent = "Org not initialized yet."; return; }

    const out = await apiPublic(`/org/check-username?orgId=${encodeURIComponent(orgId)}&username=${encodeURIComponent(username)}`);
    $("jnUserStatus").textContent = out.available ? "Username available ✅" : "Username already taken.";
  } catch (e) {
    $("jnUserStatus").textContent = e.message || "Username check failed";
  }
}, 400);

const checkLoginOrgLive = debounce(async () => {
  const orgId = String($("liOrgId").value || "").trim();
  if (!orgId) { $("liOrgStatus").textContent = ""; return; }

  try {
    const out = await apiPublic(`/org/check?orgId=${encodeURIComponent(orgId)}`);
    if (!out.exists) $("liOrgStatus").textContent = "Org not found.";
    else if (!out.initialized) $("liOrgStatus").textContent = "Org not initialized yet.";
    else $("liOrgStatus").textContent = `Org ready ✅ Users: ${out.userCount}`;
  } catch (e) {
    $("liOrgStatus").textContent = e.message || "Org check failed";
  }
}, 400);

/* -----------------------------
   Actions
------------------------------ */
async function submitRequest() {
  ok("rqOk", ""); err("rqErr", "");

  const orgName = String($("rqOrgName").value || "").trim();
  const requesterName = String($("rqRequesterName").value || "").trim();
  const requesterEmail = String($("rqRequesterEmail").value || "").trim();
  const notes = String($("rqNotes").value || "").trim();

  if (!orgName || !requesterName || !requesterEmail) {
    err("rqErr", "Organization name, your name, and your email are required.");
    return;
  }

  const out = await api("/public/org-requests", {
    method: "POST",
    body: { orgName, requesterName, requesterEmail, notes }
  });

  ok("rqOk", `Request submitted ✅\nRequest ID: ${out.requestId}\nYou’ll receive an Admin setup link after approval.`);
}

async function joinOrgSignup() {
  ok("jnOk", ""); err("jnErr", "");

  const orgId = String($("jnOrgId").value || "").trim();
  const inviteCode = String($("jnInviteCode").value || "").trim();
  const username = String($("jnUsername").value || "").trim();
  const password = String($("jnPassword").value || "");

  if (!orgId || !inviteCode || !username || !password) {
    err("jnErr", "Org ID, invite code, username, and password are required.");
    return;
  }
  if (password.length < 8) { // your server enforces 8 in signup; you can raise later
    err("jnErr", "Password must be at least 8 characters.");
    return;
  }

  // Guard: org must exist and be initialized
  const oc = await apiPublic(`/org/check?orgId=${encodeURIComponent(orgId)}`);
  if (!oc.exists) { err("jnErr", "Org not found. Submit a request first."); return; }
  if (!oc.initialized) { err("jnErr", "Org is not initialized yet. Ask your Admin / wait for setup."); return; }

  const out = await api("/auth/signup", {
    method: "POST",
    body: { signupType: "OrgType", orgId, inviteCode, username, password }
  });

  ok("jnOk", `Account created ✅\nOrg: ${out.orgId}\nRole: ${out.role}\nNow login.`);
  setTab("login");
  $("liOrgId").value = out.orgId;
  $("liUsername").value = username;
  $("liPassword").value = "";
  checkLoginOrgLive();
}

async function login() {
  ok("liOk", ""); err("liErr", "");

  const orgId = String($("liOrgId").value || "").trim();
  const username = String($("liUsername").value || "").trim();
  const password = String($("liPassword").value || "");

  if (!orgId || !username || !password) {
    err("liErr", "Org ID, username, and password are required.");
    return;
  }

  const out = await api("/auth/login", { method: "POST", body: { orgId, username, password } });

  localStorage.setItem("qm_token", out.token);
  localStorage.setItem("qm_user", JSON.stringify(out.user));

  // optional role flags if you want, but not required:
  localStorage.setItem("qm_role", out.user?.role || "");
  localStorage.setItem("qm_orgId", out.user?.orgId || orgId);
  localStorage.setItem("qm_username", out.user?.username || username);

  ok("liOk", "Logged in ✅ Redirecting…");

  if (out.user?.role === "SuperAdmin") {
    window.location.href = "/portal/.qm/super.html";
    return;
  }
  if (out.user?.role === "Admin") {
    window.location.href = "/portal/admin.html";
    return;
  }
  window.location.href = "/portal/inbox.html";
}

/* -----------------------------
   Wiring
------------------------------ */
$("tabRequest").addEventListener("click", () => setTab("request"));
$("tabJoin").addEventListener("click", () => setTab("join"));
$("tabLogin").addEventListener("click", () => setTab("login"));

$("btnRequest").addEventListener("click", () => submitRequest().catch(e => err("rqErr", e.message)));
$("btnJoin").addEventListener("click", () => joinOrgSignup().catch(e => err("jnErr", e.message)));
$("btnLogin").addEventListener("click", () => login().catch(e => err("liErr", e.message)));

$("jnOrgId")?.addEventListener("input", () => { checkJoinOrgLive(); checkJoinUsernameLive(); });
$("jnUsername")?.addEventListener("input", () => checkJoinUsernameLive());

$("liOrgId")?.addEventListener("input", () => checkLoginOrgLive());

// boot
setTab("request");
