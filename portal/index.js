const $ = (id) => document.getElementById(id);

function ok(id, msg) { const el = $(id); if (el) el.textContent = msg || ""; }
function err(id, msg) { const el = $(id); if (el) el.textContent = msg || ""; }

function debounce(fn, ms = 350) {
  let t = null;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function setTab(which) {
  const isSignup = which === "signup";
  $("tabSignup").classList.toggle("active", isSignup);
  $("tabLogin").classList.toggle("active", !isSignup);
  $("signupPanel").style.display = isSignup ? "" : "none";
  $("loginPanel").style.display = isSignup ? "none" : "";
  ok("suOk", ""); err("suErr", "");
  ok("liOk", ""); err("liErr", "");
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

// ---------- UI state ----------
function computeSignupUI() {
  const signupType = $("suSignupType").value;
  const indivMode = $("suIndividualMode").value;

  $("suInviteWrap").style.display = "none";
  $("suOrgRow").style.display = "none";
  $("suIndividualModeWrap").style.display = "none";
  $("suWantAdminRow").style.display = "none";
  $("orgSetupRedirectWrap").style.display = "none";

  if (signupType === "Individual") {
    $("suIndividualModeWrap").style.display = "";
    if (indivMode === "create") {
      $("suWantAdminRow").style.display = "";
      $("suSummary").textContent = "You’ll get a new Org ID. If Admin, you can manage users + invites.";
    } else {
      $("suOrgRow").style.display = "";
      $("suSummary").textContent = "You will join an existing org as a Member.";
    }
    return;
  }

  // OrgType
  $("suOrgRow").style.display = "";
  $("suInviteWrap").style.display = "";
  $("orgSetupRedirectWrap").style.display = "";
  $("suSummary").textContent = "You’ll join an existing org using an invite code.";
}

function wireSignupUI() {
  $("suSignupType").addEventListener("change", () => {
    computeSignupUI();
    checkOrgIdLive();
    checkUsernameLive();
  });
  $("suIndividualMode").addEventListener("change", () => {
    computeSignupUI();
    checkOrgIdLive();
    checkUsernameLive();
  });
  computeSignupUI();
}

// ---------- Live checks ----------
const checkOrgIdLive = debounce(async () => {
  const signupType = $("suSignupType").value;
  const indivMode = $("suIndividualMode").value;

  if ($("suOrgRow").style.display === "none") {
    $("suOrgStatus").textContent = "";
    return;
  }

  const orgId = String($("suOrgId").value || "").trim();
  if (!orgId) { $("suOrgStatus").textContent = ""; return; }

  try {
    const out = await apiPublic(`/org/check?orgId=${encodeURIComponent(orgId)}`);

    if (signupType === "OrgType") {
      if (!out.exists) {
        $("suOrgStatus").textContent = "Org not found. An Admin must initialize it first.";
      } else if (!out.hasAdmin) {
        $("suOrgStatus").textContent = "Org exists but has no Admin yet. Initialize as Admin first.";
      } else {
        $("suOrgStatus").textContent = `Org found ✅ Users: ${out.userCount}`;
      }
      return;
    }

    // Individual join
    if (indivMode === "join") {
      if (!out.exists) $("suOrgStatus").textContent = "Org not found.";
      else $("suOrgStatus").textContent = `Org found ✅ Users: ${out.userCount}`;
      return;
    }

    // Individual create mode doesn't need orgId, but if user typed one, warn if taken
    if (out.exists) $("suOrgStatus").textContent = "This Org ID already exists. Choose another or switch to Join.";
    else $("suOrgStatus").textContent = "Org ID is available ✅";
  } catch (e) {
    $("suOrgStatus").textContent = e.message || "Org check failed";
  }
}, 400);

const checkUsernameLive = debounce(async () => {
  const signupType = $("suSignupType").value;
  const indivMode = $("suIndividualMode").value;

  const username = String($("suUsername").value || "").trim();
  if (!username) { $("suUserStatus").textContent = ""; return; }

  // Individual create -> org is generated, can't pre-check
  if (signupType === "Individual" && indivMode === "create") {
    $("suUserStatus").textContent = "Username will be checked after org is created.";
    return;
  }

  const orgId = String($("suOrgId").value || "").trim();
  if (!orgId) { $("suUserStatus").textContent = ""; return; }

  try {
    const out = await apiPublic(`/org/check-username?orgId=${encodeURIComponent(orgId)}&username=${encodeURIComponent(username)}`);
    if (!out.orgExists) { $("suUserStatus").textContent = "Org not found yet."; return; }
    $("suUserStatus").textContent = out.available ? "Username is available ✅" : "Username is already taken.";
  } catch (e) {
    $("suUserStatus").textContent = e.message || "Username check failed";
  }
}, 400);

// ---------- Signup ----------
async function signup() {
  ok("suOk", ""); err("suErr", "");

  const signupType = String($("suSignupType").value || "Individual");
  const indivMode = String($("suIndividualMode").value || "create");

  const username = String($("suUsername").value || "").trim();
  const password = String($("suPassword").value || "");
  const orgId = String($("suOrgId").value || "").trim();
  const inviteCode = String($("suInviteCode").value || "").trim();
  const wantAdmin = String($("suWantAdmin").value || "true") === "true";

  if (!username || !password) { err("suErr", "Username and Password are required."); return; }
  if (password.length < 8) { err("suErr", "Password must be at least 8 characters."); return; }

  const body = { signupType, username, password };

  if (signupType === "Individual") {
    if (indivMode === "join") {
      if (!orgId) { err("suErr", "Org ID is required to join an existing org."); return; }
      body.orgId = orgId;
      body.wantAdmin = false;
    } else {
      body.wantAdmin = wantAdmin;
      // no orgId sent => server generates, unless you intentionally type one and want to send it
      // If you want allow custom orgId, uncomment below:
      // if (orgId) body.orgId = orgId;
    }
  } else {
    if (!orgId) { err("suErr", "Org ID is required for OrgType signup."); return; }
    if (!inviteCode) { err("suErr", "Invite code is required for OrgType signup."); return; }
    body.orgId = orgId;
    body.inviteCode = inviteCode;
  }

  const out = await api("/auth/signup", { method: "POST", body });

  ok("suOk", `Account created ✅ Role: ${out.role}\nOrg ID: ${out.orgId}\nNow login.`);
  setTab("login");
  $("liOrgId").value = out.orgId;
  $("liUsername").value = username;
  $("liPassword").value = "";
}

// ---------- Login (ROLE-BASED redirect) ----------
async function login() {
  ok("liOk", ""); err("liErr", "");

  const orgId = String($("liOrgId").value || "").trim();
  const username = String($("liUsername").value || "").trim();
  const password = String($("liPassword").value || "");

  if (!orgId || !username || !password) { err("liErr", "Org ID, Username, and Password are required."); return; }

  const out = await api("/auth/login", { method: "POST", body: { orgId, username, password } });

  sessionStorage.setItem("qm_token", out.token);
  sessionStorage.setItem("qm_user", JSON.stringify(out.user));

  // If admin, also set admin token (so admin pages don't need re-login)
  if (out.user?.role === "Admin") sessionStorage.setItem("qm_admin_token", out.token);

  ok("liOk", "Logged in ✅ Redirecting…");

  // ✅ SECURE ROLE-BASED ROUTE
  if (out.user?.role === "Admin") {
    window.location.href = "/portal/admin.html";
  } else {
    window.location.href = "/portal/inbox.html";
  }
}

// Admin init redirect
$("btnGoAdminSetup")?.addEventListener("click", () => {
  const orgId = String($("suOrgId").value || "").trim();
  const url = orgId ? `/portal/admin.html?orgId=${encodeURIComponent(orgId)}` : "/portal/admin.html";
  window.location.href = url;
});

// wires
$("tabSignup").addEventListener("click", () => setTab("signup"));
$("tabLogin").addEventListener("click", () => setTab("login"));
$("btnSignup").addEventListener("click", () => signup().catch(e => err("suErr", e.message)));
$("btnLogin").addEventListener("click", () => login().catch(e => err("liErr", e.message)));

$("suOrgId")?.addEventListener("input", () => { checkOrgIdLive(); checkUsernameLive(); });
$("suUsername")?.addEventListener("input", () => checkUsernameLive());

wireSignupUI();
