// portal/super.js
(() => {
  const $ = (id) => document.getElementById(id);

  const apiBaseEl = $("apiBase");
  const tokenEl = $("token");
  const saveTokenBtn = $("saveTokenBtn");
  const loadTokenBtn = $("loadTokenBtn");
  const refreshMeBtn = $("refreshMeBtn");
  const logoutBtn = $("logoutBtn");

  const whoEl = $("who");
  const guardMsg = $("guardMsg");
  const mainCard = $("mainCard");

  const statusSel = $("statusSel");
  const reloadBtn = $("reloadBtn");
  const tbody = $("tbody");
  const listMsg = $("listMsg");

  const toastEl = $("toast");

  // Storage keys
  const SS_SUPER = "qm_super_token";
  const SS_TOKEN = "qm_token";
  const SS_USER  = "qm_user";
  const SS_ADMIN = "qm_admin_token";
  const SS_BASE  = "qm_api_base";

  const LS_TOKEN = "qm_token";
  const LS_USER  = "qm_user";
  const LS_SUPER = "qm_super_token";
  const LS_ADMIN = "qm_admin_token";
  const LS_BASE  = "qm_api_base";

  function toast(msg) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.classList.add("show");
    setTimeout(() => toastEl.classList.remove("show"), 2200);
  }

  function getApiBase() {
    const v = String(apiBaseEl?.value || "").trim();
    return v ? v.replace(/\/+$/, "") : ""; // "" = same origin
  }

  function getToken() {
    return String(tokenEl?.value || "").trim();
  }

  function setLocked(msg) {
    if (mainCard) mainCard.style.display = "none";
    if (whoEl) whoEl.textContent = msg || "Access denied";
  }

  function setUnlocked(user) {
    if (mainCard) mainCard.style.display = "block";
    if (whoEl) whoEl.textContent = `${user.username} • ${user.role} • ${user.orgId}`;
  }

  async function api(path, { method = "GET", body } = {}) {
    const base = getApiBase();
    const url = base ? `${base}${path}` : path;

    const token = getToken();
    const headers = {};
    if (body) headers["Content-Type"] = "application/json";
    if (token) headers.Authorization = `Bearer ${token}`;

    const res = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    let data = null;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("application/json")) {
      try { data = await res.json(); } catch {}
    } else {
      try { data = await res.text(); } catch {}
    }

    if (!res.ok) {
      const msg = (data && data.error) ? data.error : `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return data;
  }

  function statusTag(status) {
    const s = String(status || "").toLowerCase();
    if (s === "approved") return `<span class="tag tagGood">approved</span>`;
    if (s === "rejected") return `<span class="tag tagBad">rejected</span>`;
    return `<span class="tag tagWarn">pending</span>`;
  }

  function esc(s) {
    return String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function renderPendingActions(id) {
    return `
      <div style="display:grid;gap:8px">
        <div>
          <label>Approve: orgId</label>
          <input class="orgId" placeholder="ex: org_acme123" />
        </div>
        <div>
          <label>Approve: first admin username</label>
          <input class="adminUsername" placeholder="ex: admin" />
        </div>
        <button class="btn btnGood approveBtn" data-id="${esc(id)}">Approve + Create Setup Link</button>

        <div class="hr"></div>

        <div>
          <label>Reject reason</label>
          <input class="rejectReason" placeholder="ex: Need business email verification" />
        </div>
        <button class="btn btnBad rejectBtn" data-id="${esc(id)}">Reject</button>

        <div class="small mono setupOut" style="word-break:break-all;display:none"></div>
        <button class="btn btnGhost copyBtn" style="display:none" type="button">Copy Setup Link</button>
      </div>
    `;
  }

  async function loadList() {
    if (listMsg) listMsg.textContent = "";
    if (tbody) tbody.innerHTML = `<tr><td colspan="4" class="small">Loading…</td></tr>`;

    try {
      const status = String(statusSel?.value || "pending");
      const data = await api(`/super/org-requests?status=${encodeURIComponent(status)}`);
      const items = Array.isArray(data?.items) ? data.items : [];

      if (!items.length) {
        tbody.innerHTML = `<tr><td colspan="4" class="small">No requests found.</td></tr>`;
        return;
      }

      tbody.innerHTML = items.map((r) => {
        const id = esc(r.id);
        const orgName = esc(r.org_name);
        const reqName = esc(r.requester_name);
        const reqEmail = esc(r.requester_email);
        const notes = esc(r.notes || "");
        const st = esc(r.status || "pending");

        const approvedOrgId = esc(r.approved_org_id || "");
        const approvedAdminUserId = esc(r.approved_admin_user_id || "");

        const createdAt = esc(r.created_at || "");
        const reviewedAt = esc(r.reviewed_at || "");
        const rejectReason = esc(r.reject_reason || "");

        return `
          <tr data-id="${id}">
            <td>${statusTag(st)}</td>
            <td>
              <div style="font-weight:700">${orgName}</div>
              <div class="small mono">${id}</div>
              <div class="small">${createdAt ? `Created: ${createdAt}` : ""}</div>
            </td>
            <td>
              <div style="font-weight:650">${reqName}</div>
              <div class="small mono">${reqEmail}</div>
              ${notes ? `<div class="small" style="margin-top:6px;color:#c7d4e8">${notes}</div>` : ""}
              ${st === "rejected" && rejectReason ? `<div class="dangerBox small" style="margin-top:8px">Reject: ${rejectReason}</div>` : ""}
              ${st === "approved" && approvedOrgId ? `<div class="small" style="margin-top:8px">OrgId: <span class="mono">${approvedOrgId}</span></div>` : ""}
              ${st === "approved" && approvedAdminUserId ? `<div class="small">AdminUserId: <span class="mono">${approvedAdminUserId}</span></div>` : ""}
              ${reviewedAt ? `<div class="small">Reviewed: ${reviewedAt}</div>` : ""}
            </td>
            <td>
              ${st === "pending" ? renderPendingActions(id) : `<div class="small">No actions for ${esc(st)}.</div>`}
            </td>
          </tr>
        `;
      }).join("");

      wireRowButtons();
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="4" class="small">Failed: ${esc(e.message)}</td></tr>`;
      if (listMsg) listMsg.textContent = `Error: ${e.message}`;
    }
  }

  function wireRowButtons() {
    const rows = tbody.querySelectorAll("tr[data-id]");
    rows.forEach((row) => {
      const approveBtn = row.querySelector(".approveBtn");
      const rejectBtn = row.querySelector(".rejectBtn");

      approveBtn?.addEventListener("click", async () => {
        const id = row.getAttribute("data-id");
        const orgId = row.querySelector(".orgId")?.value?.trim();
        const adminUsername = row.querySelector(".adminUsername")?.value?.trim();

        if (!orgId || !adminUsername) {
          toast("orgId + adminUsername required");
          return;
        }

        approveBtn.disabled = true;
        const prevText = approveBtn.textContent;
        approveBtn.textContent = "Approving…";
        try {
          const out = await api(`/super/org-requests/${encodeURIComponent(id)}/approve`, {
            method: "POST",
            body: { orgId, adminUsername }
          });

          const setupLink = out?.setupLink || "";
          const expiresAt = out?.expiresAt || "";

          const outEl = row.querySelector(".setupOut");
          const copyEl = row.querySelector(".copyBtn");

          if (outEl) {
            outEl.style.display = "block";
            outEl.textContent = `Setup Link (expires ${expiresAt}):\n${setupLink}`;
          }

          if (copyEl) {
            copyEl.style.display = "inline-flex";
            copyEl.onclick = async () => {
              try {
                await navigator.clipboard.writeText(setupLink);
                toast("Copied setup link");
              } catch {
                toast("Copy failed (browser blocked)");
              }
            };
          }

          toast("Approved ✅ (copy setup link)");
        } catch (e) {
          toast(`Approve failed: ${e.message}`);
        } finally {
          approveBtn.disabled = false;
          approveBtn.textContent = prevText || "Approve + Create Setup Link";
        }
      });

      rejectBtn?.addEventListener("click", async () => {
        const id = row.getAttribute("data-id");
        const reason = row.querySelector(".rejectReason")?.value?.trim() || "";

        rejectBtn.disabled = true;
        const prevText = rejectBtn.textContent;
        rejectBtn.textContent = "Rejecting…";
        try {
          await api(`/super/org-requests/${encodeURIComponent(id)}/reject`, {
            method: "POST",
            body: { reason }
          });
          toast("Rejected");
          await loadList();
        } catch (e) {
          toast(`Reject failed: ${e.message}`);
        } finally {
          rejectBtn.disabled = false;
          rejectBtn.textContent = prevText || "Reject";
        }
      });
    });
  }

  async function checkAccess() {
    if (guardMsg) guardMsg.textContent = "";
    try {
      const me = await api("/auth/me");
      const user = me?.user;
      if (!user) throw new Error("No user returned from /auth/me");

      if (user.role !== "SuperAdmin") {
        setLocked("Not SuperAdmin");
        if (guardMsg) guardMsg.textContent = "Blocked: role is not SuperAdmin.";
        return false;
      }

      setUnlocked(user);
      await loadList();
      return true;
    } catch (e) {
      setLocked("Checking access failed");
      if (guardMsg) guardMsg.textContent = `Access check failed: ${e.message}`;
      return false;
    }
  }

  function hardLogoutAndRedirect() {
    // Clear session storage
    sessionStorage.removeItem(SS_SUPER);
    sessionStorage.removeItem(SS_TOKEN);
    sessionStorage.removeItem(SS_USER);
    sessionStorage.removeItem(SS_ADMIN);
    sessionStorage.removeItem(SS_BASE);

    // Clear local storage (because you sometimes store there now)
    localStorage.removeItem(LS_SUPER);
    localStorage.removeItem(LS_TOKEN);
    localStorage.removeItem(LS_USER);
    localStorage.removeItem(LS_ADMIN);
    localStorage.removeItem(LS_BASE);

    // Optional: wipe any visible token field
    if (tokenEl) tokenEl.value = "";
    if (apiBaseEl) apiBaseEl.value = "";

    // Redirect to login page
    window.location.href = "/portal/index.html";
  }

  // buttons
  saveTokenBtn?.addEventListener("click", () => {
    const t = getToken();
    const b = String(apiBaseEl?.value || "").trim();

    // save to session (primary)
    if (t) {
      sessionStorage.setItem(SS_SUPER, t);
      sessionStorage.setItem(SS_TOKEN, t); // optional: keep qm_token aligned
    }
    sessionStorage.setItem(SS_BASE, b);

    // optional persistence
    localStorage.setItem(LS_TOKEN, t || "");
    localStorage.setItem(LS_SUPER, t || "");
    localStorage.setItem(LS_BASE, b);

    toast("Saved token");
  });

  loadTokenBtn?.addEventListener("click", () => {
    const t =
      sessionStorage.getItem(SS_SUPER) ||
      sessionStorage.getItem(SS_TOKEN) ||
      localStorage.getItem(LS_SUPER) ||
      localStorage.getItem(LS_TOKEN) ||
      "";

    const b =
      sessionStorage.getItem(SS_BASE) ||
      localStorage.getItem(LS_BASE) ||
      "";

    if (tokenEl) tokenEl.value = t;
    if (apiBaseEl) apiBaseEl.value = b;
    toast("Loaded saved token");
  });

  refreshMeBtn?.addEventListener("click", () => checkAccess());
  reloadBtn?.addEventListener("click", () => loadList());
  statusSel?.addEventListener("change", () => loadList());

  // ✅ FIXED LOGOUT: clear tokens AND redirect to index.html
  logoutBtn?.addEventListener("click", (e) => {
    e.preventDefault();
    toast("Logging out…");
    hardLogoutAndRedirect();
  });

  // init
  (function init() {
    const t =
      sessionStorage.getItem(SS_SUPER) ||
      sessionStorage.getItem(SS_TOKEN) ||
      localStorage.getItem(LS_SUPER) ||
      localStorage.getItem(LS_TOKEN) ||
      "";

    const b =
      sessionStorage.getItem(SS_BASE) ||
      localStorage.getItem(LS_BASE) ||
      "";

    if (tokenEl) tokenEl.value = t;
    if (apiBaseEl) apiBaseEl.value = b;

    checkAccess();
  })();
})();
