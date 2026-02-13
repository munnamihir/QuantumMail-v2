const $ = (id) => document.getElementById(id);

let token = "";
let serverBase = window.location.origin;

function ok(id, msg) { $(id).textContent = msg || ""; }
function err(id, msg) { $(id).textContent = msg || ""; }

async function api(path, { method = "GET", body = null, auth = true } = {}) {
  const headers = {};
  if (body) headers["Content-Type"] = "application/json";
  if (auth && token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${serverBase}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

/* -------------------------
   1) Create Admin
-------------------------- */
$("btnCreateAdmin").addEventListener("click", async () => {
  ok("seedOk", ""); err("seedErr", "");
  try {
    const orgId = String($("seedOrgId").value || "").trim();
    const username = String($("seedUsername").value || "").trim();
    const password = String($("seedPassword").value || "");

    if (!orgId || !username || !password) {
      throw new Error("orgId, username, password required");
    }

    const out = await api("/dev/create-admin", {
      method: "POST",
      auth: false,
      body: { orgId, username, password }
    });

    ok("seedOk", `Admin created ✅\nOrg: ${out.orgId}\nUsername: ${out.username}`);
  } catch (e) {
    err("seedErr", e?.message || String(e));
  }
});

/* -------------------------
   2) Auth
-------------------------- */
async function login() {
  ok("authOk", ""); err("authErr", "");
  try {
    const orgId = String($("orgId").value || "").trim();
    const username = String($("username").value || "").trim();
    const password = String($("password").value || "");

    if (!orgId || !username || !password) throw new Error("orgId, username, password required");

    const out = await api("/auth/login", {
      method: "POST",
      auth: false,
      body: { orgId, username, password }
    });

    token = out.token;
    $("who").textContent = `Logged in as ${out.user.username} (${out.user.role})`;
    ok("authOk", "Logged in ✅");

    await loadUsers();
  } catch (e) {
    token = "";
    $("who").textContent = "";
    err("authErr", e?.message || String(e));
  }
}

function logout() {
  token = "";
  $("who").textContent = "";
  ok("authOk", "Logged out.");
  err("authErr", "");
  $("usersTbody").innerHTML = `<tr><td colspan="5" class="muted">Login to load users…</td></tr>`;
}

$("btnLogin").addEventListener("click", login);
$("btnLogout").addEventListener("click", logout);

/* -------------------------
   3) Users
-------------------------- */
function renderUsers(users) {
  const tb = $("usersTbody");
  tb.innerHTML = "";

  if (!Array.isArray(users) || users.length === 0) {
    tb.innerHTML = `<tr><td colspan="5" class="muted">No users</td></tr>`;
    return;
  }

  for (const u of users) {
    const tr = document.createElement("tr");

    const keyPill = u.hasPublicKey
      ? `<span class="pill">Has key</span>`
      : `<span class="pill">No key</span>`;

    tr.innerHTML = `
      <td><b>${u.username}</b><div class="muted"><code>${u.userId}</code></div></td>
      <td>${u.role}</td>
      <td>${u.status || "Active"}</td>
      <td>${keyPill}</td>
      <td>
        <button data-action="clearKey" data-id="${u.userId}" class="secondary">Remove Public Key</button>
        <button data-action="deleteUser" data-id="${u.userId}" class="danger" style="margin-left:6px;">Remove User</button>
      </td>
    `;
    tb.appendChild(tr);
  }

  tb.querySelectorAll("button[data-action]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const action = btn.getAttribute("data-action");
      const userId = btn.getAttribute("data-id");

      ok("usersOk", ""); err("usersErr", "");

      try {
        if (!token) throw new Error("Login first.");

        if (action === "clearKey") {
          await api(`/admin/users/${encodeURIComponent(userId)}/clear-key`, { method: "POST" });
          ok("usersOk", "Public key removed ✅ (user must login again to re-register).");
          await loadUsers();
        }

        if (action === "deleteUser") {
          const yes = confirm("Remove this user permanently?");
          if (!yes) return;

          await api(`/admin/users/${encodeURIComponent(userId)}`, { method: "DELETE" });
          ok("usersOk", "User removed ✅");
          await loadUsers();
        }
      } catch (e) {
        err("usersErr", e?.message || String(e));
      }
    });
  });
}

async function loadUsers() {
  ok("usersOk", ""); err("usersErr", "");
  if (!token) return;

  const out = await api("/admin/users");
  renderUsers(out.users || []);
}

$("btnCreateUser").addEventListener("click", async () => {
  ok("usersOk", ""); err("usersErr", "");
  try {
    if (!token) throw new Error("Login first.");

    const username = String($("newUsername").value || "").trim();
    const password = String($("newPassword").value || "");
    const role = String($("newRole").value || "Member").trim() || "Member";

    if (!username || !password) throw new Error("username and password required");

    await api("/admin/users", {
      method: "POST",
      body: { username, password, role }
    });

    ok("usersOk", `User created ✅ (${username})`);
    $("newUsername").value = "";
    $("newPassword").value = "";
    $("newRole").value = "Member";

    await loadUsers();
  } catch (e) {
    err("usersErr", e?.message || String(e));
  }
});
