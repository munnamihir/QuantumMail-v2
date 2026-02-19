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
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function setText(id, v) {
  const el = $(id);
  if (el) el.textContent = String(v ?? "—");
}

function setKpis(out) {
  const c = out.counts || {};
  setText("kEncrypted", c.encryptedMessages);
  setText("kDecrypts", c.decrypts);
  setText("kDenied", c.deniedDecrypts);
  setText("kFailed", c.failedLogins);

  // enterprise KPIs
  const seats = out.seats || {};
  setText("kActiveSeats", `${seats.activeUsers ?? 0} / ${seats.totalUsers ?? 0}`);
  setText("kWAU", `${seats.activeUsers7d ?? 0}`);
  setText("kKeyCoverage", `${seats.keyCoveragePct ?? 0}%`);
  setText("kDecryptRate", `${out.rates?.decryptSuccessRatePct ?? 0}%`);
}

function renderTopUsers(list) {
  const tbody = $("tbodyUsers");
  if (!Array.isArray(list) || !list.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="muted">No data.</td></tr>`;
    return;
  }
  tbody.innerHTML = list.map(u => `
    <tr>
      <td>${escapeHtml(u.username || "—")}<div class="muted">${escapeHtml(u.userId || "")}</div></td>
      <td>${escapeHtml(u.role || "Member")}</td>
      <td>${escapeHtml(u.encrypts)}</td>
      <td>${escapeHtml(u.decrypts)}</td>
      <td>${escapeHtml(u.denied)}</td>
      <td>${escapeHtml(u.logins)}</td>
    </tr>
  `).join("");
}

function renderKeyHealth(out) {
  const missing = out.keyHealth?.missingKeys || [];
  const stale = out.keyHealth?.staleKeys || [];
  const staleDays = out.keyHealth?.staleKeyDays ?? 90;

  setText("kMissingKeys", out.keyHealth?.missingKeysCount ?? missing.length);
  setText("kStaleKeys", out.keyHealth?.staleKeysCount ?? stale.length);
  setText("staleKeyDaysLabel", staleDays);

  const tbMissing = $("tbodyMissingKeys");
  if (!missing.length) tbMissing.innerHTML = `<tr><td colspan="4" class="muted">None ✅</td></tr>`;
  else tbMissing.innerHTML = missing.map(u => `
    <tr>
      <td>${escapeHtml(u.username || "—")}<div class="muted">${escapeHtml(u.userId || "")}</div></td>
      <td>${escapeHtml(u.role || "Member")}</td>
      <td class="muted">${escapeHtml(u.lastLoginAt || "—")}</td>
      <td><span class="muted">Register key on next login</span></td>
    </tr>
  `).join("");

  const tbStale = $("tbodyStaleKeys");
  if (!stale.length) tbStale.innerHTML = `<tr><td colspan="4" class="muted">None ✅</td></tr>`;
  else tbStale.innerHTML = stale.map(u => `
    <tr>
      <td>${escapeHtml(u.username || "—")}<div class="muted">${escapeHtml(u.userId || "")}</div></td>
      <td>${escapeHtml(u.role || "Member")}</td>
      <td class="muted">${escapeHtml(u.publicKeyRegisteredAt || "—")}</td>
      <td><b>${escapeHtml(u.keyAgeDays ?? "—")}</b></td>
    </tr>
  `).join("");
}

function renderInvites(out) {
  const inv = out.invites || {};
  setText("kInvActive", inv.active ?? 0);
  setText("kInvUsed", inv.used ?? 0);
  setText("kInvExpired", inv.expired ?? 0);
}

function drawCore(series) {
  const ctx = $("chartCore");
  const labels = series.map(x => x.day);
  const data = {
    labels,
    datasets: [
      { label: "Encrypted", data: series.map(x => x.encrypted || 0) },
      { label: "Decrypts", data: series.map(x => x.decrypts || 0) },
      { label: "Denied", data: series.map(x => x.denied || 0) },
      { label: "Failed Logins", data: series.map(x => x.failedLogins || 0) }
    ]
  };

  if (coreChart) coreChart.destroy();
  coreChart = new Chart(ctx, { type: "line", data });
}

function drawAttachment(series) {
  const ctx = $("chartAtt");
  const labels = series.map(x => x.day);
  const vals = series.map(x => x.attachmentsBytes || 0);

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
  const staleKeyDays = Math.min(3650, Math.max(7, parseInt(($("staleKeyDays")?.value || "90"), 10) || 90));

  const out = await api(`/admin/analytics?days=${encodeURIComponent(days)}&staleKeyDays=${encodeURIComponent(staleKeyDays)}`);

  setKpis(out);
  renderInvites(out);
  renderKeyHealth(out);
  renderTopUsers(out.topUsers || []);

  const series = out.activitySeries || [];
  drawCore(series);
  drawAttachment(series);
}

$("btnRefresh").addEventListener("click", () => refresh().catch(e => setErr(e.message)));
refresh().catch(e => setErr(e.message));
