// /portal/index.js
// ✅ FULL FILE (null-safe) — fixes: Cannot read properties of null (reading 'value')

const $ = (id) => document.getElementById(id);

/* =========================
   Safe DOM helpers
========================= */
function mustEl(id) {
  const el = $(id);
  if (!el) throw new Error(`Missing required element #${id}`);
  return el;
}

function val(id) {
  const el = $(id);
  return String(el?.value ?? "").trim();
}

function setText(id, text) {
  const el = $(id);
  if (el) el.textContent = text || "";
}

function ok(id, msg) {
  setText(id, msg || "");
}

function err(id, msg) {
  setText(id, msg || "");
}

function debounce(fn, ms = 350) {
  let t = null;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function clearAllMsgs() {
  ["rqOk", "rqErr", "jnOk", "jnErr", "liOk", "liErr"].forEach((x) => {
    ok(x, "");
    err(x, "");
  });
}

/* =========================
   Tabs (null-safe)
========================= */
function setTab(which) {
  const isReq = which === "request";
  const isJoin = which === "join";
  const isLogin = which === "login";

  $("tabRequest")?.classList.toggle("active", isReq);
  $("tabJoin")?.classList.toggle("active", isJoin);
  $("tabLogin")?.classList.toggle("active", isLogin);

  if ($("requestPanel")) $("requestPanel").style.display = isReq ? "" : "none";
  if ($("joinPanel")) $("joinPanel").style.display = isJoin ? "" : "none";
  if ($("loginPanel")) $("loginPanel").style.display = isLogin ? "" : "none";

  clearAllMsgs();
}

/* =========================
   HTTP helpers
========================= */
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

/* =========================
   Live checks (Join + Login)
========================= */
const checkJoinOrgLive = debounce(async () => {
  const orgId = val("jnOrgId");
  if (!orgId) {
    setText("jnOrgStatus", "");
    return;
  }

  try {
    const out = await apiPublic(`/org/check?orgId=${encodeURIComponent(orgId)}`);
    if (!out.exists) setText("jnOrgStatus", "Org not found. Submit a request on the first tab.");
    else if (!out.initialized) setText("jnOrgStatus", "Org exists but not initialized yet. Admin must finish setup first.");
    else setText("jnOrgStatus", `Org ready ✅ Users: ${out.userCount}`);
  } catch (e) {
    setText("jnOrgStatus", e?.message || "Org check failed");
  }
}, 400);

const checkJoinUsernameLive = debounce(async () => {
  const orgId = val("jnOrgId");
  const username = val("jnUsername");
  if (!orgId || !username) {
    setText("jnUserStatus", "");
    return;
  }

  try {
    const org = await apiPublic(`/org/check?orgId=${encodeURIComponent(orgId)}`);
    if (!org.exists) {
      setText("jnUserStatus", "Org not found.");
      return;
    }
    if (!org.initialized) {
      setText("jnUserStatus", "Org not initialized yet.");
      return;
    }

    const out = await apiPublic(
      `/org/check-username?orgId=${encodeURIComponent(orgId)}&username=${encodeURIComponent(username)}`
    );
    setText("jnUserStatus", out.available ? "Username available ✅" : "Username already taken.");
  } catch (e) {
    setText("jnUserStatus", e?.message || "Username check failed");
  }
}, 400);

const checkLoginOrgLive = debounce(async () => {
  const orgId = val("liOrgId");
  if (!orgId) {
    setText("liOrgStatus", "");
    return;
  }

  try {
    const out = await apiPublic(`/org/check?orgId=${encodeURIComponent(orgId)}`);
    if (!out.exists) setText("liOrgStatus", "Org not found.");
    else if (!out.initialized) setText("liOrgStatus", "Org not initialized yet.");
    else setText("liOrgStatus", `Org ready ✅ Users: ${out.userCount}`);
  } catch (e) {
    setText("liOrgStatus", e?.message || "Org check failed");
  }
}, 400);

/* =========================
   Actions
========================= */
async function submitRequest() {
  ok("rqOk", "");
  err("rqErr", "");

  const companyName = val("rqCompanyName");
  const companyId = val("rqCompanyId");
  const orgName = val("rqOrgName");
  const requesterName = val("rqRequesterName");
  const requesterEmail = val("rqRequesterEmail");
  const notes = val("rqNotes");

  if (!companyName) {
    err("rqErr", "Company name is required.");
    return;
  }
  if (!orgName || !requesterName || !requesterEmail) {
    err("rqErr", "Organization name, your name, and your email are required.");
    return;
  }

  const out = await api("/public/org-requests", {
    method: "POST",
    body: { companyName, companyId, orgName, requesterName, requesterEmail, notes }
  });

  ok(
    "rqOk",
    `Request submitted ✅\nRequest ID: ${out.requestId}\nYou’ll receive an Admin setup link after approval.`
  );
}

async function joinOrgSignup() {
  ok("jnOk", "");
  err("jnErr", "");

  const orgId = val("jnOrgId");
  const inviteCode = val("jnInviteCode");
  const username = val("jnUsername");
  const password = String($("jnPassword")?.value ?? ""); // keep raw (no trim)
  const email = val("jnEmail"); // optional

  if (!orgId || !inviteCode || !username || !password) {
    err("jnErr", "Org ID, invite code, username, and password are required.");
    return;
  }
  if (password.length < 8) {
    err("jnErr", "Password must be at least 8 characters.");
    return;
  }

  const oc = await apiPublic(`/org/check?orgId=${encodeURIComponent(orgId)}`);
  if (!oc.exists) {
    err("jnErr", "Org not found. Submit a request first.");
    return;
  }
  if (!oc.initialized) {
    err("jnErr", "Org is not initialized yet. Ask your Admin / wait for setup.");
    return;
  }

  const out = await api("/auth/signup", {
    method: "POST",
    body: { signupType: "OrgType", orgId, inviteCode, username, password, email }
  });

  ok("jnOk", `Account created ✅\nOrg: ${out.orgId}\nRole: ${out.role}\nNow login.`);
  setTab("login");

  if ($("liOrgId")) $("liOrgId").value = out.orgId;
  if ($("liUsername")) $("liUsername").value = username;
  if ($("liPassword")) $("liPassword").value = "";
  if ($("liEmail") && email) $("liEmail").value = email;

  checkLoginOrgLive();
}

async function login() {
  ok("liOk", "");
  err("liErr", "");

  const orgId = val("liOrgId");
  const username = val("liUsername");
  const password = String($("liPassword")?.value ?? "");

  if (!orgId || !username || !password) {
    err("liErr", "Org ID, username, and password are required.");
    return;
  }

  const out = await api("/auth/login", { method: "POST", body: { orgId, username, password } });

  localStorage.setItem("qm_token", out.token);
  localStorage.setItem("qm_user", JSON.stringify(out.user));

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

/* =========================
   Recovery
========================= */
async function forgotUsername() {
  ok("liOk", "");
  err("liErr", "");

  const orgId = val("liOrgId");
  const email = val("liEmail");

  if (!orgId || !email) {
    err("liErr", "Org ID and Email are required for recovery.");
    return;
  }

  const out = await api("/auth/forgot-username", {
    method: "POST",
    body: { orgId, email }
  });

  ok("liOk", out.message || "If an account exists, you’ll receive an email shortly.");
}

async function forgotPassword() {
  ok("liOk", "");
  err("liErr", "");

  const orgId = val("liOrgId");
  const email = val("liEmail");

  if (!orgId || !email) {
    err("liErr", "Org ID and Email are required for password reset.");
    return;
  }

  const out = await api("/auth/forgot-password", {
    method: "POST",
    body: { orgId, email }
  });

  ok("liOk", out.message || "If an account exists, you’ll receive a reset link shortly.");
}

/* =========================
   Wiring (null-safe)
========================= */
$("tabRequest")?.addEventListener("click", () => setTab("request"));
$("tabJoin")?.addEventListener("click", () => setTab("join"));
$("tabLogin")?.addEventListener("click", () => setTab("login"));

$("btnRequest")?.addEventListener("click", () => submitRequest().catch((e) => err("rqErr", e.message)));
$("btnJoin")?.addEventListener("click", () => joinOrgSignup().catch((e) => err("jnErr", e.message)));
$("btnLogin")?.addEventListener("click", () => login().catch((e) => err("liErr", e.message)));

$("btnForgotUsername")?.addEventListener("click", () => forgotUsername().catch((e) => err("liErr", e.message)));
$("btnForgotPassword")?.addEventListener("click", () => forgotPassword().catch((e) => err("liErr", e.message)));

$("jnOrgId")?.addEventListener("input", () => {
  checkJoinOrgLive();
  checkJoinUsernameLive();
});
$("jnUsername")?.addEventListener("input", () => checkJoinUsernameLive());

$("liOrgId")?.addEventListener("input", () => checkLoginOrgLive());

/* =========================
   Boot
========================= */
(function boot() {
  // default tab
  setTab("request");

  // Auto-tab via URL: /portal/index.html?tab=login&orgId=org_demo
  const u = new URL(window.location.href);
  const tab = (u.searchParams.get("tab") || "").toLowerCase();
  if (tab === "login") setTab("login");
  if (tab === "join") setTab("join");
  if (tab === "request") setTab("request");

  const orgFromUrl = u.searchParams.get("orgId");
  if (orgFromUrl && $("liOrgId")) {
    $("liOrgId").value = orgFromUrl;
    checkLoginOrgLive();
  }
})();
