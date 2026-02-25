// /portal/companies.js
(() => {
  const $ = (id) => document.getElementById(id);

  const apiBaseEl = $("apiBase");
  const tokenEl = $("token");
  const saveTokenBtn = $("saveTokenBtn");
  const loadTokenBtn = $("loadTokenBtn");
  const reloadBtn = $("reloadBtn");
  const logoutBtn = $("logoutBtn");

  const whoEl = $("who");
  const guardMsg = $("guardMsg");
  const mainCard = $("mainCard");
  const msgEl = $("msg");
  const companiesWrap = $("companiesWrap");

  // modal toast
  const toastModal = $("toast");
  const toastText = $("toastText");
  const toastCloseBtn = $("toastCloseBtn");

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
    if (!toastModal || !toastText) return;
    toastText.textContent = String(msg || "");
    toastModal.style.display = "block";
  }
  function toastClose() {
    if (!toastModal) return;
    toastModal.style.display = "none";
  }
  toastCloseBtn?.addEventListener("click", toastClose);
  toastModal?.addEventListener("click", (e) => {
    if (e.target === toastModal) toastClose();
  });

  function esc(s) {
    return String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function getApiBase() {
    const v = String(apiBaseEl?.value || "").trim();
    return v ? v.replace(/\/+$/, "") : "";
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
      const m = (data && data.error) ? data.error : `HTTP ${res.status}`;
      throw new Error(m);
    }
    return data;
  }

  function fmtTime(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "—";
    return d.toLocaleString();
  }

  function companyCardHtml(c) {
    const orgs = Array.isArray(c.orgs) ? c.orgs : [];
    const orgCount = c.totals?.orgs ?? orgs.length;
    const seats = c.totals?.seats ?? 0;
    const keysAvg = c.totals?.keysPctAvg ?? 0;

    const headerBadges = `
      <div class="orgLine" style="margin-top:10px">
        <span class="badge"><span class="badgeDot"></span><strong>Orgs:</strong> ${esc(orgCount)}</span>
        <span class="badge"><span class="badgeDot"></span><strong>Seats:</strong> ${esc(seats)}</span>
        <span class="badge"><span class="badgeDot"></span><strong>Avg key coverage:</strong> ${esc(keysAvg)}%</span>
        <span class="badge"><span class="badgeDot"></span><strong>ID:</strong> <span class="mono">${esc(c.companyId)}</span></span>
      </div>
    `;

    const orgRows = orgs.map((o) => {
      const seatsTotal = o.seats?.totalUsers || 0;
      const admins = o.seats?.admins || 0;
      const members = o.seats?.members || 0;
      const keysPct = o.seats?.keyCoveragePct || 0;

      return `
        <div class="item" style="margin-top:10px">
          <div>
            <div class="itemTitle">${esc(o.orgName || o.orgId)}</div>
            <div class="muted mono">${esc(o.orgId)}</div>
            <div class="help">Last activity: ${esc(fmtTime(o.lastActivityAt))}</div>
            <div class="orgLine">
              <span class="badge"><span class="badgeDot"></span><strong>Seats:</strong> ${esc(seatsTotal)}</span>
              <span class="badge"><span class="badgeDot"></span><strong>Admins:</strong> ${esc(admins)}</span>
              <span class="badge"><span class="badgeDot"></span><strong>Members:</strong> ${esc(members)}</span>
              <span class="badge"><span class="badgeDot"></span><strong>Keys:</strong> ${esc(keysPct)}%</span>
            </div>
          </div>
        </div>
      `;
    }).join("");

    return `
      <div class="card" style="margin-top:14px">
        <h2 style="margin:0">${esc(c.companyName || c.companyId)}</h2>
        ${headerBadges}
        ${orgRows || `<div class="muted" style="margin-top:10px">No orgs.</div>`}
      </div>
    `;
  }

  function renderCompanies(companies) {
    if (!companiesWrap) return;

    if (!Array.isArray(companies) || companies.length === 0) {
      companiesWrap.innerHTML = `<div class="item"><div class="muted">No approved orgs yet.</div></div>`;
      return;
    }

    // Using your "rich" look by stacking cards (company card contains org items)
    companiesWrap.innerHTML = companies.map(companyCardHtml).join("");
  }

  async function loadCompanies() {
    if (msgEl) msgEl.textContent = "";
    if (companiesWrap) companiesWrap.innerHTML = `<div class="item"><div class="muted">Loading…</div></div>`;

    try {
      const out = await api("/super/companies/overview");
      renderCompanies(out?.companies || []);
    } catch (e) {
      if (companiesWrap) companiesWrap.innerHTML = "";
      if (msgEl) msgEl.textContent = `Companies error: ${e.message}`;
    }
  }

  async function checkAccess() {
    if (guardMsg) guardMsg.textContent = "—";
    try {
      const me = await api("/auth/me");
      const user = me?.user;
      if (!user) throw new Error("No user returned from /auth/me");

      if (user.role !== "SuperAdmin") {
        setLocked("Not SuperAdmin");
        if (guardMsg) guardMsg.textContent = "Blocked: role is not SuperAdmin.";
        return false;
      }

      if (guardMsg) guardMsg.textContent = "OK";
      setUnlocked(user);
      return true;
    } catch (e) {
      setLocked("Checking access failed");
      if (guardMsg) guardMsg.textContent = `Access check failed: ${e.message}`;
      return false;
    }
  }

  function hardLogoutAndRedirect() {
    sessionStorage.removeItem(SS_SUPER);
    sessionStorage.removeItem(SS_TOKEN);
    sessionStorage.removeItem(SS_USER);
    sessionStorage.removeItem(SS_ADMIN);
    sessionStorage.removeItem(SS_BASE);

    localStorage.removeItem(LS_SUPER);
    localStorage.removeItem(LS_TOKEN);
    localStorage.removeItem(LS_USER);
    localStorage.removeItem(LS_ADMIN);
    localStorage.removeItem(LS_BASE);

    if (tokenEl) tokenEl.value = "";
    if (apiBaseEl) apiBaseEl.value = "";

    window.location.href = "/portal/index.html";
  }

  saveTokenBtn?.addEventListener("click", () => {
    const t = getToken();
    const b = String(apiBaseEl?.value || "").trim();

    if (t) {
      sessionStorage.setItem(SS_SUPER, t);
      sessionStorage.setItem(SS_TOKEN, t);
    }
    sessionStorage.setItem(SS_BASE, b);

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

  reloadBtn?.addEventListener("click", () => loadCompanies());

  logoutBtn?.addEventListener("click", (e) => {
    e.preventDefault();
    toast("Logging out…");
    setTimeout(() => hardLogoutAndRedirect(), 250);
  });

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

    (async () => {
      const ok = await checkAccess();
      if (ok) await loadCompanies();
    })();
  })();
})();
