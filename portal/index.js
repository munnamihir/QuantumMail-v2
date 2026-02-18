const $ = (id) => document.getElementById(id);

function ok(id, msg) { const el=$(id); if (el) el.textContent = msg||""; }
function err(id, msg) { const el=$(id); if (el) el.textContent = msg||""; }

function debounce(fn, ms = 350) {
  let t = null;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function setFieldState(inputEl, msgEl, state, msg) {
  if (!inputEl || !msgEl) return;
  msgEl.textContent = msg || "";
  inputEl.classList.remove("goodField", "badField");
  if (state === "good") inputEl.classList.add("goodField");
  if (state === "bad") inputEl.classList.add("badField");
}

async function apiPublic(path) {
  const res = await fetch(path);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

async function api(path, { method="GET", body=null, token="" } = {}) {
  const headers = {};
  if (body) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

// ---------------- Tabs ----------------
function setTab(which) {
  const isSignup = which === "signup";
  $("tabSignup").classList.toggle("active", isSignup);
  $("tabLogin").classList.toggle("active", !isSignup);
  $("signupPanel").style.display = isSignup ? "" : "none";
  $("loginPanel").style.display = isSignup ? "none" : "";
  ok("suOk",""); err("suErr",""); ok("liOk",""); err("liErr","");
}

// ---------------- Signup UI logic ----------------
function updateSummary() {
  const signupType = $("suSignupType")?.value;
  const indivMode = $("suIndividualMode")?.value;
  const wantAdmin = String($("suWantAdmin")?.value || "true") === "true";

  let text = "—";
  if (signupType === "Individual") {
    if (indivMode === "create") text = wantAdmin ? "Creates a new org + you become Admin (also Inbox)." : "Creates a new org + you become Member.";
    else text = "Joins an existing org by Org ID.";
  } else {
    text = "Joins an existing org using Org ID + one-time join code.";
  }

  const el = $("suSummary");
  if (el) el.textContent = text;
}

function computeSignupUI() {
  const signupType = $("suSignupType")?.value;
  const indivMode = $("suIndividualMode")?.value;

  const orgRow = $("suOrgRow");
  const inviteWrap = $("suInviteWrap");
  const indivModeWrap = $("suIndividualModeWrap");
  const wantAdminRow = $("suWantAdminRow");
  const setupRedirect = $("orgSetupRedirectWrap");

  if (setupRedirect) setupRedirect.style.display = "none";

  if (signupType === "Individual") {
    if (indivModeWrap) indivModeWrap.style.display = "";
    if (wantAdminRow) wantAdminRow.style.display = "";
    if (inviteWrap) inviteWrap.style.display = "none";

    if (orgRow) orgRow.style.display = (indivMode === "join") ? "" : "none";
  } else {
    // OrgType
    if (indivModeWrap) indivModeWrap.style.display = "none";
    if (wantAdminRow) wantAdminRow.style.display = "none";
    if (orgRow) orgRow.style.display = "";
    if (inviteWrap) inviteWrap.style.display = "";

    if (setupRedirect) setupRedirect.style.display = "";
  }

  updateSummary();
}

function wireSignupUI() {
  $("suSignupType")?.addEventListener("change", () => { computeSignupUI(); checkOrgIdLive(); checkUsernameLive(); });
  $("suIndividualMode")?.addEventListener("change", () => { computeSignupUI(); checkOrgIdLive(); checkUsernameLive(); });
  $("suWantAdmin")?.addEventListener("change", updateSummary);
  computeSignupUI();
}

// ---------------- Live checks (signup) ----------------
const checkOrgIdLive = debounce(async () => {
  const orgRowVisible = $("suOrgRow")?.style.display !== "none";
  if (!orgRowVisible) {
    setFieldState($("suOrgId"), $("suOrgStatus"), null, "");
    return;
  }

  const orgId = String($("suOrgId")?.value || "").trim();
  const signupType = String($("suSignupType")?.value || "Individual");
  const indivMode = String($("suIndividualMode")?.value || "create");

  if (!orgId) {
    setFieldState($("suOrgId"), $("suOrgStatus"), null, "");
    return;
  }

  try {
    const out = await apiPublic(`/org/check?orgId=${encodeURIComponent(orgId)}`);

    if (signupType === "OrgType") {
      if (!out.exists) {
        setFieldState($("suOrgId"), $("suOrgStatus"), "bad", "Org not found. Click “Initialize Organization as Admin”.");
      } else if (!out.initialized) {
        setFieldState($("suOrgId"), $("suOrgStatus"), "bad", "Org exists but not initialized. Initialize as Admin first.");
      } else {
        setFieldState($("suOrgId"), $("suOrgStatus"), "good", `Org found ✅ Users: ${out.userCount}`);
      }
      return;
    }

    // Individual join
    if (indivMode === "join") {
      if (!out.exists) setFieldState($("suOrgId"), $("suOrgStatus"), "bad", "Org not found.");
      else if (!out.initialized) setFieldState($("suOrgId"), $("suOrgStatus"), "bad", "Org not initialized yet.");
      else setFieldState($("suOrgId"), $("suOrgStatus"), "good", `Org found ✅ Users: ${out.userCount}`);
      return;
    }

    setFieldState($("suOrgId"), $("suOrgStatus"), null, "");
  } catch (e) {
    setFieldState($("suOrgId"), $("suOrgStatus"), "bad", e.message || "Org check failed");
  }
}, 400);

const checkUsernameLive = debounce(async () => {
  const signupType = String($("suSignupType")?.value || "Individual");
  const indivMode = String($("suIndividualMode")?.value || "create");

  const username = String($("suUsername")?.value || "").trim();
  const orgId = String($("suOrgId")?.value || "").trim();

  if (!username) {
    setFieldState($("suUsername"), $("suUserStatus"), null, "");
    return;
  }

  // Individual create => orgId generated server-side, can’t pre-check
  if (signupType === "Individual" && indivMode === "create") {
    setFieldState($("suUsername"), $("suUserStatus"), null, "Username will be validated when org is created.");
    return;
  }

  if (!orgId) {
    setFieldState($("suUsername"), $("suUserStatus"), null, "");
    return;
  }

  try {
    const out = await apiPublic(`/org/check-username?orgId=${encodeURIComponent(orgId)}&username=${encodeURIComponent(username)}`);
    if (!out.orgExists) {
      setFieldState($("suUsername"), $("suUserStatus"), "bad", "Org not found.");
      return;
    }
    if (out.available) setFieldState($("suUsername"), $("suUserStatus"), "good", "Username is available ✅");
    else setFieldState($("suUsername"), $("suUserStatus"), "bad", "Username already taken.");
  } catch (e) {
    setFieldState($("suUsername"), $("suUserStatus"), "bad", e.message || "Username check failed");
  }
}, 400);

// ---------------- Signup submit ----------------
async function signup() {
  ok("suOk",""); err("suErr","");

  const signupType = String($("suSignupType")?.value || "Individual");
  const indivMode = String($("suIndividualMode")?.value || "create");

  const username = String($("suUsername")?.value || "").trim();
  const password = String($("suPassword")?.value || "");
  const orgId = String($("suOrgId")?.value || "").trim();
  const inviteCode = String($("suInviteCode")?.value || "").trim();
  const wantAdmin = String($("suWantAdmin")?.value || "true") === "true";

  if (!username || !password) { err("suErr","Username and Password are required."); return; }
  if (password.length < 8) { err("suErr","Password must be at least 8 characters."); return; }

  const body = { signupType, username, password };

  if (signupType === "Individual") {
    if (indivMode === "join") {
      if (!orgId) { err("suErr","Org ID is required to join an existing org."); return; }
      body.orgId = orgId;
      body.wantAdmin = false;
    } else {
      body.wantAdmin = wantAdmin; // server generates orgId
    }
  } else {
    if (!orgId) { err("suErr","Org ID is required for OrgType signup."); return; }
    if (!inviteCode) { err("suErr","One-time join code is required for OrgType signup."); return; }
    body.orgId = orgId;
    body.inviteCode = inviteCode;
  }

  const out = await api("/auth/signup", { method:"POST", body });

  const createdOrg = out.orgId ? `\nYour Org ID: ${out.orgId}` : "";
  ok("suOk", `Account created ✅ Role: ${out.role || "Member"}${createdOrg}\nNow login.`);

  setTab("login");
  $("liOrgId").value = out.orgId || orgId || "";
  $("liUsername").value = username;
  $("liPassword").value = "";
}

// ---------------- Login live checks ----------------
const checkLoginOrgLive = debounce(async () => {
  const orgId = String($("liOrgId")?.value || "").trim();
  if (!orgId) { setFieldState($("liOrgId"), $("liOrgStatus"), null, ""); return; }
  try {
    const out = await apiPublic(`/org/check?orgId=${encodeURIComponent(orgId)}`);
    if (!out.exists) setFieldState($("liOrgId"), $("liOrgStatus"), "bad", "Org not found.");
    else if (!out.initialized) setFieldState($("liOrgId"), $("liOrgStatus"), "bad", "Org not initialized.");
    else setFieldState($("liOrgId"), $("liOrgStatus"), "good", `Org found ✅ Users: ${out.userCount}`);
  } catch (e) {
    setFieldState($("liOrgId"), $("liOrgStatus"), "bad", e.message || "Org check failed");
  }
}, 400);

const checkLoginUserLive = debounce(async () => {
  const orgId = String($("liOrgId")?.value || "").trim();
  const username = String($("liUsername")?.value || "").trim();
  if (!orgId || !username) { setFieldState($("liUsername"), $("liUserStatus"), null, ""); return; }

  try {
    const out = await apiPublic(`/org/check-username?orgId=${encodeURIComponent(orgId)}&username=${encodeURIComponent(username)}`);
    if (!out.orgExists) { setFieldState($("liUsername"), $("liUserStatus"), "bad", "Org not found."); return; }
    // login: if available=true => username not used
    if (out.available) setFieldState($("liUsername"), $("liUserStatus"), "bad", "User not found.");
    else setFieldState($("liUsername"), $("liUserStatus"), "good", "User exists ✅");
  } catch (e) {
    setFieldState($("liUsername"), $("liUserStatus"), "bad", e.message || "User check failed");
  }
}, 400);

// ---------------- Login submit ----------------
async function login() {
  ok("liOk",""); err("liErr","");

  const orgId = String($("liOrgId")?.value || "").trim();
  const username = String($("liUsername")?.value || "").trim();
  const password = String($("liPassword")?.value || "");

  if (!orgId || !username || !password) { err("liErr","Org ID, Username, and Password are required."); return; }

  const out = await api("/auth/login", { method:"POST", body:{ orgId, username, password } });

  sessionStorage.setItem("qm_token", out.token);
  sessionStorage.setItem("qm_user", JSON.stringify(out.user));

  // Let admin pages use same token (no separate login)
  if (out.user?.role === "Admin") {
    sessionStorage.setItem("qm_admin_token", out.token);
  } else {
    sessionStorage.removeItem("qm_admin_token");
  }

  ok("liOk","Logged in ✅ Redirecting…");

  // Always go Inbox; admin can open dashboard from inbox nav.
  window.location.href = "/portal/inbox.html";
}

// ---------------- Wiring ----------------
$("tabSignup")?.addEventListener("click", () => setTab("signup"));
$("tabLogin")?.addEventListener("click", () => setTab("login"));

$("btnSignup")?.addEventListener("click", () => signup().catch(e => err("suErr", e.message)));
$("btnLogin")?.addEventListener("click", () => login().catch(e => err("liErr", e.message)));

$("btnGoAdminSetup")?.addEventListener("click", () => {
  const orgId = $("suOrgId")?.value?.trim();
  window.location.href = orgId ? `/portal/admin.html?orgId=${encodeURIComponent(orgId)}` : "/portal/admin.html";
});

$("suOrgId")?.addEventListener("input", () => { checkOrgIdLive(); checkUsernameLive(); });
$("suUsername")?.addEventListener("input", () => checkUsernameLive());

$("liOrgId")?.addEventListener("input", () => { checkLoginOrgLive(); checkLoginUserLive(); });
$("liUsername")?.addEventListener("input", () => checkLoginUserLive());

wireSignupUI();
checkLoginOrgLive();
