(() => {
  const $ = (id) => document.getElementById(id);

  const apiBaseEl = $("apiBase");
  const tokenEl = $("token");
  const saveTokenBtn = $("saveTokenBtn");
  const loadTokenBtn = $("loadTokenBtn");
  const reloadCompaniesBtn = $("reloadCompaniesBtn");
  const logoutBtn = $("logoutBtn");

  const whoEl = $("who");
  const companiesWrap = $("companiesWrap");
  const companiesMsg = $("companiesMsg");
  const toastEl = $("toast");

  const SS_TOKEN = "qm_token";
  const SS_SUPER = "qm_super_token";
  const SS_BASE  = "qm_api_base";

  const LS_TOKEN = "qm_token";
  const LS_SUPER = "qm_super_token";
  const LS_BASE  = "qm_api_base";

  function toast(msg) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.classList.add("show");
    setTimeout(() => toastEl.classList.remove("show"), 2200);
  }

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

  function fmtTime(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "—";
    return d.toLocaleString();
  }

  function renderCompanies(companies) {
    if (!companiesWrap) return;

    if (!Array.isArray(companies) || companies.length === 0) {
      companiesWrap.innerHTML = `<div class="small">No approved orgs yet.</div>`;
      return;
    }

    companiesWrap.innerHTML = companies.map((c) => {
      const orgs = Array.isArray(c.orgs) ? c.orgs : [];
      const orgsHtml = orgs.map((o) => `
        <div class="orgRow">
          <div class="orgLeft">
            <div class="orgTitle">${esc(o.orgName || o.orgId)}</div>
            <div class="small mono">${esc(o.orgId)}</div>
            <div class="small">Last activity: ${esc(fmtTime(o.lastActivityAt))}</div>
          </div>
          <div class="kpis">
            <span class="kpi">Seats: <b>${esc(o.seats?.totalUsers || 0)}</b></span>
            <span class="kpi">Admins: <b>${esc(o.seats?.admins || 0)}</b></span>
            <span class="kpi">Members: <b>${esc(o.seats?.members || 0)}</b></span>
            <span class="kpi">Keys: <b>${esc(o.seats?.keyCoveragePct || 0)}%</b></span>
          </div>
        </div>
      `).join("");

      const orgCount = c.totals?.orgs ?? orgs.length;
      const seats = c.totals?.seats ?? 0;
      const keysAvg = c.totals?.keysPctAvg ?? 0;

      return `
        <div class="companyCard">
          <div class="companyHead">
            <div>
              <div class="companyName">${esc(c.companyName || c.companyId)}</div>
              <div class="companyMeta">
                Orgs: <b>${esc(orgCount)}</b> •
                Seats: <b>${esc(seats)}</b> •
                Avg key coverage: <b>${esc(keysAvg)}%</b>
              </div>
              <div class="small mono" style="margin-top:6px">${esc(c.companyId)}</div>
            </div>
          </div>
          <div class="orgList">${orgsHtml || `<div class="small">No orgs.</div>`}</div>
        </div>
      `;
    }).join("");
  }

  async function loadCompanies() {
    if (companiesMsg) companiesMsg.textContent = "";
    if (companiesWrap) companiesWrap.innerHTML = `<div class="small">Loading companies…</div>`;

    try {
      const out = await api("/super/companies/overview");
      renderCompanies(out?.companies || []);
    } catch (e) {
      if (companiesWrap) companiesWrap.innerHTML = "";
      if (companiesMsg) companiesMsg.textContent = `Companies error: ${e.message}`;
    }
  }

  async function checkAccess() {
    try {
      const me = await api("/auth/me");
      const user = me?.user;
      if (!user) throw new Error("No user returned from /auth/me");

      if (user.role !== "SuperAdmin") {
        if (whoEl) whoEl.textContent = "Access denied (not SuperAdmin)";
        throw new Error("Not SuperAdmin");
      }

      if (whoEl) whoEl.textContent = `${user.username} • ${user.role} • ${user.orgId}`;
      return true;
    } catch (e) {
      if (whoEl) whoEl.textContent = `Access check failed`;
      if (companiesMsg) companiesMsg.textContent = `Access error: ${e.message}`;
      return false;
    }
  }

  function hardLogoutAndRedirect() {
    sessionStorage.removeItem(SS_SUPER);
    sessionStorage.removeItem(SS_TOKEN);
    sessionStorage.removeItem(SS_BASE);

    localStorage.removeItem(LS_SUPER);
    localStorage.removeItem(LS_TOKEN);
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

  reloadCompaniesBtn?.addEventListener("click", () => loadCompanies());

  logoutBtn?.addEventListener("click", (e) => {
    e.preventDefault();
    toast("Logging out…");
    hardLogoutAndRedirect();
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
