const $ = (id) => document.getElementById(id);
let token = "";

async function api(path) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

function readTokenFromMemoryHint() {
  // Admin pages keep token in memory only.
  // Easiest: login on /portal/admin.html in same tab session,
  // then navigate here; token is NOT shared automatically.
  // So we ask user to re-login here if you want, but to keep it simple:
  // We'll store token in sessionStorage for admin pages only.
  token = sessionStorage.getItem("qm_admin_token") || "";
}

function setErr(msg) { $("err").textContent = msg || ""; }
function setOut(msg) { $("out").textContent = msg || ""; }

async function refresh() {
  setErr(""); setOut("Loading…");
  const minutes = Math.max(5, parseInt($("minutes").value || "60", 10) || 60);

  if (!token) throw new Error("No admin token. Login on Admin page first.");

  const out = await api(`/admin/alerts?minutes=${encodeURIComponent(minutes)}`);
  setOut(`Denied decrypts: ${out.summary.denied} • Failed logins: ${out.summary.failedLogins}`);

  const list = $("list");
  list.innerHTML = "";

  const alerts = Array.isArray(out.alerts) ? out.alerts : [];
  if (!alerts.length) {
    list.innerHTML = `<div class="muted" style="margin-top:10px;">No alerts ✅</div>`;
    return;
  }

  for (const a of alerts) {
    const div = document.createElement("div");
    div.className = `alert ${a.severity || ""}`.trim();
    div.innerHTML = `<b>${a.code}</b><div class="muted" style="margin-top:4px;">${a.message}</div>`;
    list.appendChild(div);
  }
}

$("btnRefresh").addEventListener("click", () => refresh().catch(e => setErr(e.message)));

readTokenFromMemoryHint();
refresh().catch(e => setErr(e.message));
