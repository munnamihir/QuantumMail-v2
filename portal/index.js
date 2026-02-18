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


function setTab(which) {
  const isSignup = which === "signup";
  $("tabSignup").classList.toggle("active", isSignup);
  $("tabLogin").classList.toggle("active", !isSignup);
  $("signupPanel").style.display = isSignup ? "" : "none";
  $("loginPanel").style.display = isSignup ? "none" : "";
  ok("suOk",""); err("suErr",""); ok("liOk",""); err("liErr","");
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

// -------- Signup UI logic --------
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
    indivModeWrap.style.display = "";
    wantAdminRow.style.display = "";
    inviteWrap.style.display = "none";

    if (indivMode === "create") {
      orgRow.style.display = "none";
    } else {
      orgRow.style.display = "";
    }
    return;
  }

  // OrgType
  indivModeWrap.style.display = "none";
  wantAdminRow.style.display = "none";
  orgRow.style.display = "";
  inviteWrap.style.display = "";

  // show redirect option
  if (setupRedirect) setupRedirect.style.display = "";
}

function wireSignupUI() {
  $("suSignupType")?.addEventListener("change", computeSignupUI);
  $("suIndividualMode")?.addEventListener("change", computeSignupUI);
  computeSignupUI();
}

// -------- Signup submit --------
async function signup() {
  ok("suOk",""); err("suErr","");

  const signupType = String($("suSignupType")?.value || "Individual");
  const indivMode = String($("suIndividualMode")?.value || "create");

  const username = String($("suUsername")?.value || "").trim();
  const password = String($("suPassword")?.value || "");
  const orgId = String($("suOrgId")?.value || "").trim();
  const inviteCode = String($("suInviteCode")?.value || "").trim();
  const wantAdmin = String($("suWantAdmin")?.value || "true") === "true";

  if (!username || !password) {
    err("suErr","Username and Password are required.");
    return;
  }

  // Build body according to your new backend contract:
  // POST /auth/signup
  // Individual: orgId optional (create generates), wantAdmin for create; join uses orgId
  // OrgType: orgId + inviteCode required
  const body = { signupType, username, password };

  if (signupType === "Individual") {
    if (indivMode === "join") {
      if (!orgId) { err("suErr","Org ID is required to join an existing org."); return; }
      body.orgId = orgId;
      body.wantAdmin = false;
    } else {
      // create new
      body.wantAdmin = wantAdmin; // usually true
      // do not send orgId (server generates). If you want allow custom orgId, you can send it optionally.
    }
  } else {
    // OrgType
    if (!orgId) { err("suErr","Org ID is required for OrgType signup."); return; }
    if (!inviteCode) { err("suErr","One-time join code is required for OrgType signup."); return; }
    body.orgId = orgId;
    body.inviteCode = inviteCode;
  }

  const out = await api("/auth/signup", { method:"POST", body });

  // If server generated orgId, show it beautifully
  const createdOrg = out.orgId ? `\nYour Org ID: ${out.orgId}\n(Share this to let others join.)` : "";
  ok("suOk", `Account created ✅ Role: ${out.role || "Member"}${createdOrg}\nNow login.`);

  setTab("login");

  // pre-fill login
  if (out.orgId) $("liOrgId").value = out.orgId;
  else if (orgId) $("liOrgId").value = orgId;

  $("liUsername").value = username;
  $("liPassword").value = "";
}

// -------- Login submit --------
async function login() {
  ok("liOk",""); err("liErr","");

  const orgId = String($("liOrgId").value || "").trim();
  const username = String($("liUsername").value || "").trim();
  const password = String($("liPassword").value || "");

  if (!orgId || !username || !password) {
    err("liErr","Org ID, Username, and Password are required.");
    return;
  }

  const out = await api("/auth/login", { method:"POST", body:{ orgId, username, password } });

  sessionStorage.setItem("qm_token", out.token);
  sessionStorage.setItem("qm_user", JSON.stringify(out.user));

  // ALSO store admin token for admin pages so you don't have two logins
  // (Admin pages currently read qm_admin_token)
  if (out.user?.role === "Admin") {
    sessionStorage.setItem("qm_admin_token", out.token);
  }

  ok("liOk","Logged in ✅ Redirecting…");

  // ✅ Admin should also see Inbox (no duplicate account)
  // Admin can still go to /portal/admin.html from Inbox header/nav.
  window.location.href = "/portal/inbox.html";
}

$("tabSignup").addEventListener("click", () => setTab("signup"));
$("tabLogin").addEventListener("click", () => setTab("login"));
$("btnSignup").addEventListener("click", () => signup().catch(e => err("suErr", e.message)));
$("btnLogin").addEventListener("click", () => login().catch(e => err("liErr", e.message)));
$("btnGoAdminSetup")?.addEventListener("click", () => {
  const orgId = $("suOrgId")?.value?.trim();
  if (orgId) {
    // Pass orgId in query so admin page can pre-fill
    window.location.href = `/portal/admin.html?orgId=${encodeURIComponent(orgId)}`;
  } else {
    window.location.href = "/portal/admin.html";
  }
});

wireSignupUI();
