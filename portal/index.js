const $ = (id) => document.getElementById(id);

function ok(id, msg) { const el=$(id); if (el) el.textContent = msg||""; }
function err(id, msg) { const el=$(id); if (el) el.textContent = msg||""; }

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

async function signup() {
  ok("suOk",""); err("suErr","");

  const orgId = String($("suOrgId").value || "").trim();
  const username = String($("suUsername").value || "").trim();
  const password = String($("suPassword").value || "");
  const role = String($("suRole").value || "Member");

  if (!orgId || !username || !password) {
    err("suErr","Org ID, Username, and Password are required.");
    return;
  }

  const out = await api("/auth/signup", {
    method:"POST",
    body:{ orgId, username, password, role }
  });

  ok("suOk",`Account created as ${out.role} ✅ You can now login.`);
  setTab("login");

  $("liOrgId").value = orgId;
  $("liUsername").value = username;
}


async function login() {
  ok("liOk",""); err("liErr","");

  const orgId = String($("liOrgId").value || "").trim();
  const username = String($("liUsername").value || "").trim();
  const password = String($("liPassword").value || "");

  if (!orgId || !username || !password) {
    err("liErr","Org ID, Username, and Password are required.");
    return;
  }

  const out = await api("/auth/login", {
    method:"POST",
    body:{ orgId, username, password }
  });

  sessionStorage.setItem("qm_token", out.token);
  sessionStorage.setItem("qm_user", JSON.stringify(out.user));

  ok("liOk","Logged in ✅ Redirecting…");

  if (out.user.role === "Admin") {
    window.location.href = "/portal/admin.html";
  } else {
    window.location.href = "/portal/inbox.html";
  }
}


$("tabSignup").addEventListener("click", () => setTab("signup"));
$("tabLogin").addEventListener("click", () => setTab("login"));
$("btnSignup").addEventListener("click", () => signup().catch(e => err("suErr", e.message)));
$("btnLogin").addEventListener("click", () => login().catch(e => err("liErr", e.message)));
