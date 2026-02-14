const $ = (id) => document.getElementById(id);
let token = sessionStorage.getItem("qm_admin_token") || "";
let coreChart = null;
let attChart = null;

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

function setKpis(c) {
  $("kEncrypted").textContent = String(c.encryptedMessages ?? "—");
  $("kDecrypts").textContent = String(c.decrypts ?? "—");
  $("kDenied").textContent = String(c.deniedDecrypts ?? "—");
  $("kFailed").textContent = String(c.failedLogins ?? "—");
}

function renderTopUsers(list) {
  const tbody = $("tbodyUsers");
  if (!Array.isArray(list) || !list.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="muted">No data.</td></tr>`;
    return;
  }
  tbody.innerHTML = list.map(u => `
    <tr>
      <td>${escapeHtml(u.userId)}</td>
      <td>${escapeHtml(u.encrypts)}</td>
      <td>${escapeHtml(u.decrypts)}</td>
      <td>${escapeHtml(u.denied)}</td>
      <td>${escapeHtml(u.logins)}</td>
    </tr>
  `).join("");
}

function drawCore(counts) {
  const ctx = $("chartCore");
  const data = {
    labels: ["Encrypt", "Decrypt", "Denied", "Login Fail"],
    datasets: [{
      label: "Count",
      data: [
        counts.encryptedMessages || 0,
        counts.decrypts || 0,
        counts.deniedDecrypts || 0,
        counts.failedLogins || 0
      ]
    }]
  };

  if (coreChart) coreChart.destroy();
  coreChart = new Chart(ctx, { type: "bar", data });
}

function drawAttachment(series) {
  const ctx = $("chartAtt");
  const labels = series.map(x => x.day);
  const vals = series.map(x => x.attachmentBytes || 0);

  const data = {
    labels,
    datasets: [{ label: "Attachment Bytes", data: vals }]
  };

  if (attChart) attChart.destroy();
  attChart = new Chart(ctx, { type: "line", data });
}

async function refresh() {
  setErr("");
  if (!token) throw new Error("No admin token. Login on Admin page first.");

  const days = Math.min(365, Math.max(1, parseInt($("days").value || "30", 10) || 30));
  const out = await api(`/admin/analytics?days=${encodeURIComponent(days)}`);

  setKpis(out.counts || {});
  renderTopUsers(out.topUsers || []);
  drawCore(out.counts || {});
  drawAttachment(out.attachmentSeries || []);
}

$("btnRefresh").addEventListener("click", () => refresh().catch(e => setErr(e.message)));
refresh().catch(e => setErr(e.message));
