const $ = (id) => document.getElementById(id);
let token = sessionStorage.getItem("qm_admin_token") || "";

async function api(path) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

function setErr(msg) { $("err").textContent = msg || ""; }
function escapeHtml(s) {
  return String(s || "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}

async function refresh() {
  setErr("");
  if (!token) throw new Error("No admin token. Login on Admin page first.");

  const limit = Math.min(2000, Math.max(10, parseInt($("limit").value || "200", 10) || 200));
  const out = await api(`/admin/audit?limit=${encodeURIComponent(limit)}`);

  const act = ($("action").value || "").trim().toLowerCase();
  const usr = ($("user").value || "").trim().toLowerCase();

  const items = (out.items || []).filter(x => {
    const aok = !act || String(x.action || "").toLowerCase().includes(act);
    const uok = !usr || String(x.username || "").toLowerCase().includes(usr);
    return aok && uok;
  });

  const tbody = $("tbody");
  tbody.innerHTML = items.map(x => `
    <tr>
      <td>${escapeHtml(new Date(x.at).toLocaleString())}</td>
      <td><b>${escapeHtml(x.action)}</b></td>
      <td>${escapeHtml(x.username || x.userId || "—")}</td>
      <td>${escapeHtml(x.ip || "—")}</td>
      <td class="muted">${escapeHtml(JSON.stringify(x, null, 0))}</td>
    </tr>
  `).join("") || `<tr><td colspan="5" class="muted">No results.</td></tr>`;
}

$("btnRefresh").addEventListener("click", () => refresh().catch(e => setErr(e.message)));
refresh().catch(e => setErr(e.message));
