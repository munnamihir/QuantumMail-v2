// portal/audit.js
const $ = (id) => document.getElementById(id);
let token = "";

function ok(msg){ $("ok").textContent = msg || ""; if (msg) $("err").textContent = ""; }
function err(msg){ $("err").textContent = msg || ""; if (msg) $("ok").textContent = ""; }

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function applyHashDefaults() {
  // #orgId=org_demo
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

  const limit = Math.min(parseInt($("limit").value || "200", 10) || 200, 1000);
  const out = await api(`/admin/audit?limit=${encodeURIComponent(String(limit))}`);

  const items = out.items || [];
  const tbody = $("tbody");
  if (!tbody) return;

  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="muted">No audit events found.</td></tr>`;
    return;
  }

  tbody.innerHTML = items.map((x) => {
    const details = { ...x };
    delete details.id; delete details.at; delete details.action; delete details.ua; delete details.ip;
    const detailStr = escapeHtml(JSON.stringify(details, null, 0));
    return `
      <tr>
        <td>${escapeHtml(x.at || "")}</td>
        <td><b>${escapeHtml(x.action || "")}</b></td>
        <td>${escapeHtml(x.userId || "")}</td>
        <td><code>${detailStr}</code></td>
      </tr>
    `;
  }).join("");

  ok(`Loaded ${items.length} events ✅`);
}

$("btnLogin")?.addEventListener("click", () => login().catch(e => err(e.message)));
$("btnRefresh")?.addEventListener("click", () => refresh().catch(e => err(e.message)));

applyHashDefaults();
