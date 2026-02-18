const $ = (id) => document.getElementById(id);

function ok(id, msg) { const el=$(id); if (el) el.textContent = msg||""; }
function err(id, msg) { const el=$(id); if (el) el.textContent = msg||""; }

function getToken() { return sessionStorage.getItem("qm_token") || ""; }
function getUser() {
  try { return JSON.parse(sessionStorage.getItem("qm_user") || "null"); }
  catch { return null; }
}

async function api(path, { method="GET", body=null } = {}) {
  const token = getToken();
  if (!token) throw new Error("Not logged in.");

  const headers = { Authorization: `Bearer ${token}` };
  if (body) headers["Content-Type"] = "application/json";

  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

function fmt(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

function render(items) {
  const list = $("list");
  if (!list) return;

  if (!Array.isArray(items) || items.length === 0) {
    list.innerHTML = `<div class="muted" style="padding:12px;">No encrypted messages yet.</div>`;
    return;
  }

  list.innerHTML = items.map((m) => `
    <div class="item">
      <div class="itemMain">
        <div class="itemTitle">Encrypted message</div>
        <div class="muted">
          ${m.from ? `From: <b>${m.from}</b> • ` : ``}
          ${fmt(m.createdAt)}
          ${m.attachmentCount ? ` • Attachments: ${m.attachmentCount}` : ``}
        </div>
      </div>
      <div class="itemActions">
        <a class="btn primary" href="/m/${encodeURIComponent(m.id)}">Decrypt</a>
      </div>
    </div>
  `).join("");
}

async function refresh() {
  err("inboxErr","");
  const out = await api("/api/inbox");
  render(out.items || []);
}

function logout() {
  sessionStorage.removeItem("qm_token");
  sessionStorage.removeItem("qm_user");
  window.location.href = "/portal/index.html";
}

// Profile modal
function openProfile() {
  ok("pwOk",""); err("pwErr","");
  const u = getUser();
  $("profileMeta").textContent = u ? `${u.username}@${u.orgId} • ${u.role}` : "—";
  $("curPw").value = ""; $("newPw").value = ""; $("newPw2").value = "";
  $("profileModal").style.display = "";
}
function closeProfile() { $("profileModal").style.display = "none"; }

async function changePassword() {
  ok("pwOk",""); err("pwErr","");
  const currentPassword = String($("curPw").value || "");
  const newPassword = String($("newPw").value || "");
  const newPassword2 = String($("newPw2").value || "");

  if (!currentPassword || !newPassword) { err("pwErr","Current and new password are required."); return; }
  if (newPassword.length < 8) { err("pwErr","New password must be at least 8 characters."); return; }
  if (newPassword !== newPassword2) { err("pwErr","Confirmation does not match."); return; }

  await api("/auth/change-password", { method:"POST", body:{ currentPassword, newPassword } });
  ok("pwOk","Password updated ✅");
  $("curPw").value = ""; $("newPw").value = ""; $("newPw2").value = "";
}

(function init(){
  const token = getToken();
  const u = getUser();
  if (!token || !u) return logout();

  $("who").textContent = `${u.username}@${u.orgId} • ${u.role}`;
  $("btnRefresh").addEventListener("click", () => refresh().catch(e => err("inboxErr", e.message)));
  $("btnLogout").addEventListener("click", logout);

  $("btnProfile").addEventListener("click", openProfile);
  $("btnCloseProfile").addEventListener("click", closeProfile);
  $("profileModal").addEventListener("click", (e) => { if (e.target?.id === "profileModal") closeProfile(); });
  $("btnChangePw").addEventListener("click", () => changePassword().catch(e => err("pwErr", e.message)));

  refresh().catch(e => err("inboxErr", e.message));
})();
