// /portal/recover.js
(() => {
  const $ = (id) => document.getElementById(id);

  const apiBaseEl = $("apiBase");
  const orgIdEl = $("orgId");
  const emailEl = $("email");

  const tabUser = $("tabUser");
  const tabPass = $("tabPass");

  const sendBtn = $("sendBtn");
  const saveBtn = $("saveBtn");
  const goResetLink = $("goResetLink");

  const msgEl = $("msg");
  const errEl = $("err");

  const LS_BASE = "qm_api_base";
  const LS_ORG = "qm_org_id";
  const LS_EMAIL = "qm_recovery_email";

  let mode = "username"; // username | password

  function setMsg(s) {
    if (msgEl) msgEl.textContent = String(s || "");
    if (errEl) errEl.textContent = "";
  }
  function setErr(s) {
    if (errEl) errEl.textContent = String(s || "");
    if (msgEl) msgEl.textContent = "";
  }

  function normalizeBase(v) {
    const s = String(v || "").trim();
    return s ? s.replace(/\/+$/, "") : "";
  }

  function readQueryPrefill() {
    const u = new URL(window.location.href);
    const base = u.searchParams.get("base") || "";
    const orgId = u.searchParams.get("orgId") || "";
    if (base && apiBaseEl) apiBaseEl.value = base;
    if (orgId && orgIdEl) orgIdEl.value = orgId;
  }

  async function api(path, body) {
    const base = normalizeBase(apiBaseEl?.value);
    const url = base ? `${base}${path}` : path;

    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {})
    });

    const ct = res.headers.get("content-type") || "";
    const data = ct.includes("application/json") ? await res.json().catch(() => null) : await res.text().catch(() => null);

    if (!res.ok) {
      const err = (data && data.error) ? data.error : `HTTP ${res.status}`;
      throw new Error(err);
    }
    return data;
  }

  function setMode(next) {
    mode = next === "password" ? "password" : "username";
    tabUser?.classList.toggle("active", mode === "username");
    tabPass?.classList.toggle("active", mode === "password");
    setMsg("");
    setErr("");
  }

  function saveLocal() {
    localStorage.setItem(LS_BASE, normalizeBase(apiBaseEl?.value));
    localStorage.setItem(LS_ORG, String(orgIdEl?.value || "").trim());
    localStorage.setItem(LS_EMAIL, String(emailEl?.value || "").trim().toLowerCase());
    setMsg("Saved.");
  }

  function loadLocal() {
    const base = localStorage.getItem(LS_BASE) || "";
    const orgId = localStorage.getItem(LS_ORG) || "";
    const email = localStorage.getItem(LS_EMAIL) || "";
    if (apiBaseEl && !apiBaseEl.value) apiBaseEl.value = base;
    if (orgIdEl && !orgIdEl.value) orgIdEl.value = orgId;
    if (emailEl && !emailEl.value) emailEl.value = email;
  }

  async function send() {
    setMsg("");
    setErr("");

    const orgId = String(orgIdEl?.value || "").trim();
    const email = String(emailEl?.value || "").trim().toLowerCase();

    if (!orgId || !email) {
      setErr("Org ID and Email are required.");
      return;
    }

    try {
      saveLocal();

      if (mode === "username") {
        // ✅ Correct backend route
        const out = await api("/auth/forgot-username", { orgId, email });
        setMsg(out?.message || "If an account exists, you will receive an email shortly.");
      } else {
        // ✅ Correct backend route
        const out = await api("/auth/forgot-password", { orgId, email });
        setMsg(out?.message || "If an account exists, you’ll receive a reset link shortly.");
      }
    } catch (e) {
      setErr(`Request failed: ${e.message}`);
    }
  }

  tabUser?.addEventListener("click", () => setMode("username"));
  tabPass?.addEventListener("click", () => setMode("password"));

  sendBtn?.addEventListener("click", send);
  saveBtn?.addEventListener("click", saveLocal);

  goResetLink?.addEventListener("click", (e) => {
    e.preventDefault();
    const base = normalizeBase(apiBaseEl?.value);
    const orgId = String(orgIdEl?.value || "").trim();
    const u = new URL("/portal/reset.html", window.location.origin);
    if (base) u.searchParams.set("base", base);
    if (orgId) u.searchParams.set("orgId", orgId);
    window.location.href = u.toString();
  });

  // init
  readQueryPrefill();
  loadLocal();
  setMode("username");
})();
