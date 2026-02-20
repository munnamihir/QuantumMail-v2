// portal/audit.js
const $ = (id) => document.getElementById(id);

function getToken() { return localStorage.getItem("qm_token") || ""; }
function getUser() {
  try { return JSON.parse(localStorage.getItem("qm_user") || "null"); }
  catch { return null; }
}
function requireAdminOrBounce() {
  const t = getToken();
  const u = getUser();
  const ok = Boolean(t && u && (u.role === "Admin" || u.role === "SuperAdmin"));
  if (!ok) window.location.href = "/portal/index.html";
  return ok;
}

async function api(path) {
  const token = getToken();
  const headers = { Authorization: `Bearer ${token}` };
  const res = await fetch(path, { headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

function setErr(msg) { const e = $("err"); if (e) e.textContent = msg || ""; }

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}

async function refresh() {
  setErr("");
  requireAdminOrBounce();

  const limitEl = $("limit");
  const limit = Math.min(2000, Math.max(10, parseInt(limitEl?.value || "200", 10) || 200));

  const out = await api(`/admin/audit?limit=${encodeURIComponent(limit)}`);

  const act = String($("action")?.value || "").trim().toLowerCase();
  const usr = String($("user")?.value || "").trim().toLowerCase();

  const items = (out.items || []).filter(x => {
    const aok = !act || String(x.action || "").toLowerCase().includes(act);
    const uok = !usr || String(x.username || "").toLowerCase().includes(usr);
    return aok && uok;
  });

  const tbody = $("tbody");
  if (!tbody) return;

  tbody.innerHTML = items.map(x => `
    <tr>
      <td>${escapeHtml(new Date(x.at).toLocaleString())}</td>
      <td><b>${escapeHtml(x.action || "")}</b></td>
      <td>${escapeHtml(x.username || x.userId || "—")}</td>
      <td>${escapeHtml(x.ip || "—")}</td>
      <td class="muted">${escapeHtml(JSON.stringify(x))}</td>
    </tr>
  `).join("") || `<tr><td colspan="5" class="muted">No results.</td></tr>`;
}

// wiring
$("btnRefresh")?.addEventListener("click", () => refresh().catch(e => setErr(e.message)));
refresh().catch(e => setErr(e.message));
