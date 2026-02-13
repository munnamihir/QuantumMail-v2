// portal/admin.js

const $ = (id) => document.getElementById(id);

let token = "";
let session = { orgId: "", username: "" };

// ---------- helpers ----------
function setText(id, text) {
  const el = $(id);
  if (el) el.textContent = text || "";
}

function showOk(id, msg) {
  setText(id, msg || "");
}

function showErr(id, msg) {
  setText(id, msg || "");
}

function setSessionBadge() {
  const who = $("who");
  const dot = $("sessionDot");
  const st = $("sessionText");

  if (token) {
    if (who) who.textContent = `${session.username}@${session.orgId}`;
    if (dot) { dot.classList.remove("bad"); dot.classList.add("good"); }
    if (st) st.textContent = "Session: active";
  } else {
    if (who) who.textContent = "Not logged in";
    if (dot) { dot.classList.remove("good"); dot.classList.remove("bad"); }
    if (st) st.textContent = "Session: none";
  }
}

async function api(path, { method = "GET", body = null, auth = true } = {}) {
  const headers = {};
  if (auth && token) headers.Authorization = `Bearer ${token}`;
  if (body) headers["Content-Type"] = "application/json";

  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

// ---------- Create Admin ----------
async function createAdmin() {
  showOk("seedOk", "");
  showErr("seedErr", "");

  const orgId = String($("seedOrgId")?.value || "").trim();
  const username = String($("seedUsername")?.value || "").trim();
  const password = String($("seedPassword")?.value || "");

  if (!orgId || !username || !password) {
    showErr("seedErr", "orgId, username, and password are required.");
    return;
  }

  // You MUST have a matching server endpoint for this.
  // If you currently only have /dev/seed-admin, update server to accept username/password.
  // Here we call a future-proof route first, then fallback to /dev/seed-admin.
  try {
    const out = await api("/admin/bootstrap", {
      method: "POST",
      auth: false,
      body: { orgId, username, password }
    });
    showOk("seedOk", `Admin created ✅\norgId: ${out.orgId}\nusername: ${out.username || username}`);
    return;
  } catch (e) {
    // fallback to your existing /dev/seed-admin if bootstrap is not implemented
    try {
      const out2 = await api("/dev/seed-admin", {
        method: "POST",
        auth: false,
        body: { orgId }
      });
      showOk(
        "seedOk",
        `Seeded admin ✅ (legacy)\norgId: ${out2.orgId}\nadmin: ${out2.admin}\npassword: ${out2.password}\n\n(Next: implement /admin/bootstrap to allow custom username/password.)`
      );
    } catch (e2) {
      showErr("seedErr", e2?.message || String(e2));
    }
  }
}

// ---------- Login / Logout ----------
async function login() {
  showOk("authOk", "");
  showErr("authErr", "");

  const orgId = String($("orgId")?.value || "").trim();
  const username = String($("username")?.value || "").trim();
  const password = String($("password")?.value || "");

  if (!orgId || !username || !password) {
    showErr("authErr", "orgId, username, and password are required.");
    return;
  }

  try {
    const out = await api("/auth/login", {
      method: "POST",
      auth: false,
      body: { orgId, username, password }
    });

    token = out.token;
    session = { orgId, username };

    setSessionBadge();
    showOk("authOk", `Logged in ✅\nrole: ${out?.user?.role || "?"}\npublicKey: ${out?.user?.hasPublicKey ? "yes" : "no"}`);

    await loadUsers(); // auto-load
  } catch (e) {
    token = "";
    session = { orgId: "", username: "" };
    setSessionBadge();
    showErr("authErr", e?.message || String(e));
  }
}

function logout() {
  token = "";
  session = { orgId: "", username: "" };
  setSessionBadge();

  showOk("authOk", "Logged out.");
  showErr("authErr", "");
  showOk("usersOk", "");
  showErr("usersErr", "");

  const tbody = $("usersTbody");
  if (tbody) tbody.innerHTML = `<tr><td colspan="5" class="muted">Login to load users…</td></tr>`;
}

// ---------- Users ----------
function renderUsers(users) {
  const tbody = $("usersTbody");
  if (!tbody) return;

  if (!Array.isArray(users) || users.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="muted">No users found.</td></tr>`;
    return;
  }

  tbody.innerHTML = users
    .map((u) => {
      const keyText = u.hasPublicKey ? "✅" : "—";
      const status = u.status || "Active";
      const role = u.role || "Member";

      // NOTE:
      // Your backend currently has: GET/POST /admin/users
      // To support remove user / clear key you will need server endpoints (we can add next):
      // DELETE /admin/users/:id
      // POST /admin/users/:id/clear-key

      return `
        <tr>
          <td><b>${escapeHtml(u.username || "")}</b><br/><span class="muted">${escapeHtml(u.userId || "")}</span></td>
          <td>${escapeHtml(role)}</td>
          <td>${escapeHtml(status)}</td>
          <td>${keyText}</td>
          <td>
            <button class="secondary" data-action="clearKey" data-id="${escapeAttr(u.userId)}" ${u.hasPublicKey ? "" : "disabled"}>
              Clear Public Key
            </button>
            <button class="danger" data-action="removeUser" data-id="${escapeAttr(u.userId)}">
              Remove User
            </button>
          </td>
        </tr>
      `;
    })
    .join("");

  // row button handlers
  tbody.querySelectorAll("button[data-action]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const action = btn.getAttribute("data-action");
      const userId = btn.getAttribute("data-id");
      if (!userId) return;

      if (action === "removeUser") await removeUser(userId);
      if (action === "clearKey") await clearUserKey(userId);
    });
  });
}

async function loadUsers() {
  showOk("usersOk", "");
  showErr("usersErr", "");

  if (!token) {
    showErr("usersErr", "Login required.");
    return;
  }

  try {
    const out = await api("/admin/users");
    renderUsers(out.users || []);
    showOk("usersOk", `Loaded ${out?.users?.length || 0} user(s).`);
  } catch (e) {
    showErr("usersErr", e?.message || String(e));
  }
}

async function createUser() {
  showOk("usersOk", "");
  showErr("usersErr", "");

  if (!token) {
    showErr("usersErr", "Login required.");
    return;
  }

  const username = String($("newUsername")?.value || "").trim();
  const password = String($("newPassword")?.value || "");
  const role = String($("newRole")?.value || "Member").trim() || "Member";

  if (!username || !password) {
    showErr("usersErr", "New username and password are required.");
    return;
  }

  try {
    await api("/admin/users", {
      method: "POST",
      body: { username, password, role }
    });

    showOk("usersOk", `User created ✅ (${username})`);
    $("newUsername").value = "";
    $("newPassword").value = "";
    await loadUsers();
  } catch (e) {
    showErr("usersErr", e?.message || String(e));
  }
}

// These require backend endpoints (next step on server).
async function removeUser(userId) {
  showOk("usersOk", "");
  showErr("usersErr", "");

  if (!token) return showErr("usersErr", "Login required.");

  const yes = confirm("Remove this user? This cannot be undone.");
  if (!yes) return;

  try {
    await api(`/admin/users/${encodeURIComponent(userId)}`, { method: "DELETE" });
    showOk("usersOk", "User removed ✅");
    await loadUsers();
  } catch (e) {
    showErr("usersErr", e?.message || String(e));
  }
}

async function clearUserKey(userId) {
  showOk("usersOk", "");
  showErr("usersErr", "");

  if (!token) return showErr("usersErr", "Login required.");

  const yes = confirm("Clear this user's public key? They will need to login again to re-register.");
  if (!yes) return;

  try {
    await api(`/admin/users/${encodeURIComponent(userId)}/clear-key`, { method: "POST" });
    showOk("usersOk", "Public key cleared ✅");
    await loadUsers();
  } catch (e) {
    showErr("usersErr", e?.message || String(e));
  }
}

// ---------- Audit modal ----------
function openAuditModal() {
  const back = $("auditModalBackdrop");
  if (back) back.style.display = "flex";
}

function closeAuditModal() {
  const back = $("auditModalBackdrop");
  if (back) back.style.display = "none";
}

function renderAudit(items) {
  const tbody = $("auditTbody");
  if (!tbody) return;

  if (!Array.isArray(items) || items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="muted">No audit records.</td></tr>`;
    return;
  }

  tbody.innerHTML = items.map((it) => {
    const at = escapeHtml(it.at || "");
    const userId = escapeHtml(it.userId || "—");
    const action = escapeHtml(it.action || "");
    const details = escapeHtml(JSON.stringify(stripBaseFields(it), null, 0));
    return `
      <tr>
        <td>${at}</td>
        <td><code>${userId}</code></td>
        <td><b>${action}</b></td>
        <td style="max-width:520px;"><span class="muted">${details}</span></td>
      </tr>
    `;
  }).join("");
}

function stripBaseFields(it) {
  // keep details but remove duplicate base fields to reduce noise
  const clone = { ...it };
  delete clone.at;
  delete clone.userId;
  delete clone.orgId;
  delete clone.action;
  delete clone.id;
  delete clone.ip;
  delete clone.ua;
  return clone;
}

async function loadAudit() {
  showErr("auditErr", "");
  showOk("auditOk", "");

  if (!token) {
    showErr("auditErr", "Login required.");
    return;
  }

  try {
    const out = await api("/admin/audit?limit=250");
    renderAudit(out.items || []);
    showOk("auditOk", `Loaded ${out?.items?.length || 0} audit item(s).`);
  } catch (e) {
    showErr("auditErr", e?.message || String(e));
  }
}

// ---------- Analytics nav ----------
function goAnalytics() {
  // Same origin: /portal/analytics.html
  window.location.href = "/portal/analytics.html";
}

// ---------- utilities ----------
function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function escapeAttr(s) {
  return escapeHtml(s).replace(/"/g, "&quot;");
}

// ---------- wire up ----------
$("btnCreateAdmin")?.addEventListener("click", createAdmin);
$("btnLogin")?.addEventListener("click", login);
$("btnLogout")?.addEventListener("click", logout);

$("btnCreateUser")?.addEventListener("click", createUser);
$("btnRefreshUsers")?.addEventListener("click", loadUsers);

$("btnAudit")?.addEventListener("click", async () => {
  openAuditModal();
  await loadAudit();
});
$("btnAuditClose")?.addEventListener("click", closeAuditModal);
$("btnAuditRefresh")?.addEventListener("click", loadAudit);

// click outside modal to close
$("auditModalBackdrop")?.addEventListener("click", (e) => {
  if (e.target && e.target.id === "auditModalBackdrop") closeAuditModal();
});

$("btnAnalytics")?.addEventListener("click", goAnalytics);

// init
setSessionBadge();
