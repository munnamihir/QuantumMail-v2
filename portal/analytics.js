// portal/analytics.js
const $ = (id) => document.getElementById(id);
let token = "";

function ok(msg){ $("ok").textContent = msg || ""; if (msg) $("err").textContent = ""; }
function err(msg){ $("err").textContent = msg || ""; if (msg) $("ok").textContent = ""; }

function applyHashDefaults() {
  const h = new URLSearchParams((location.hash || "").replace(/^#/, ""));
  const orgId = h.get("orgId");
  if (orgId && $("orgId")) $("orgId").value = orgId;
}

async function api(path) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

async function login() {
  ok(""); err("");
  const orgId = String($("orgId").value || "").trim();
  const username = String($("username").value || "").trim();
  const password = String($("password").value || "");
  if (!orgId || !username || !password) throw new Error("Org Id, Username, Password required.");

  const res = await fetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type":"application/json" },
    body: JSON.stringify({ orgId, username, password })
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Login failed (${res.status})`);

  token = data.token;
  ok(`Logged in ✅ as ${data.user?.username}@${data.user?.orgId}`);
}

async function refresh() {
  ok(""); err("");
  if (!token) throw new Error("Login first.");

  const [usersOut, auditOut, keysOut] = await Promise.all([
    api("/admin/users"),
    api("/admin/audit?limit=500"),
    api("/admin/keys")
  ]);

  const users = usersOut.users || [];
  const auditItems = auditOut.items || [];
  const keys = keysOut || {};

  const totalUsers = users.length;
  const withKey = users.filter(u => !!u.hasPublicKey).length;
  const admins = users.filter(u => String(u.role || "").toLowerCase() === "admin").length;

  $("tUsers").textContent = String(totalUsers);
  $("tKeys").textContent = String(withKey);
  $("tAdmins").textContent = String(admins);
  $("tAudit").textContent = String(auditItems.length);

  $("keysDump").textContent = JSON.stringify(keys, null, 2);

  ok("Analytics refreshed ✅");
}

$("btnLogin")?.addEventListener("click", () => login().catch(e => err(e.message)));
$("btnRefresh")?.addEventListener("click", () => refresh().catch(e => err(e.message)));

applyHashDefaults();
