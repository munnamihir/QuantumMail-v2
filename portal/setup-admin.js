// portal/setup-admin.js
(() => {
  const $ = (id) => document.getElementById(id);

  const setErr = (m) => { $("err").textContent = m || ""; };
  const setOk  = (m) => { $("ok").textContent = m || ""; };

  const setMErr = (m) => { $("mErr").textContent = m || ""; };
  const setMOk  = (m) => { $("mOk").textContent = m || ""; };

  const qs = new URLSearchParams(location.search);
  const orgId = qs.get("orgId") || "";
  const token = qs.get("token") || "";

  let verified = false;
  let email = "";

  async function getJson(path) {
    const res = await fetch(path);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
    return data;
  }

  async function postJson(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
    return data;
  }

  function openModal() {
    $("backdrop").style.display = "flex";
  }
  function closeModal() {
    $("backdrop").style.display = "none";
  }

  function syncUI() {
    $("btnShowActivate").disabled = !verified;
    $("activateBox").style.display = verified ? "block" : "none";
    $("btnVerify").disabled = verified;

    if (verified) {
      setOk("Email verified ✅ You can activate your admin account now.");
    } else {
      setOk("");
    }
  }

  async function loadInfo() {
    setErr(""); setOk("");
    if (!orgId || !token) throw new Error("Missing orgId/token in link.");

    $("orgId").value = orgId;

    // ✅ NEW: server tells us which email this setup is for
    const info = await getJson(`/public/setup-admin-info?orgId=${encodeURIComponent(orgId)}&token=${encodeURIComponent(token)}`);

    email = info.email || "";
    verified = !!info.emailVerified;

    $("email").value = email || "—";
    $("mEmail").value = email || "—";

    syncUI();
  }

  async function sendCode() {
    setMErr(""); setMOk("");
    if (!orgId || !token) { setMErr("Missing orgId/token."); return; }

    $("btnSendCode").disabled = true;
    const prev = $("btnSendCode").textContent;
    $("btnSendCode").textContent = "Sending…";
    try {
      await postJson("/auth/setup-admin/send-code", { orgId, token });
      setMOk("Code sent ✅ Check your email.");
    } catch (e) {
      setMErr(e.message);
    } finally {
      $("btnSendCode").disabled = false;
      $("btnSendCode").textContent = prev || "Send Code";
    }
  }

  async function verifyCode() {
    setMErr(""); setMOk("");

    const code = String($("mCode").value || "").trim();
    if (!/^\d{6}$/.test(code)) {
      setMErr("Enter a valid 6-digit code.");
      return;
    }

    $("btnVerifyCode").disabled = true;
    const prev = $("btnVerifyCode").textContent;
    $("btnVerifyCode").textContent = "Verifying…";
    try {
      await postJson("/auth/setup-admin/verify-code", { orgId, token, code });
      verified = true;
      setMOk("Verified ✅");
      syncUI();
      closeModal();
    } catch (e) {
      setMErr(e.message);
    } finally {
      $("btnVerifyCode").disabled = false;
      $("btnVerifyCode").textContent = prev || "Verify";
    }
  }

  async function activate() {
    setErr(""); setOk("");
    if (!verified) { setErr("Verify email first."); return; }

    const newPassword = String($("pw").value || "");
    if (newPassword.length < 12) { setErr("New password must be at least 12 characters."); return; }

    $("btnActivateNow").disabled = true;
    const prev = $("btnActivateNow").textContent;
    $("btnActivateNow").textContent = "Activating…";
    try {
      await postJson("/auth/setup-admin", { orgId, token, newPassword });
      setOk("Activated ✅ You can now login as Admin.");
      $("pw").value = "";
    } catch (e) {
      setErr(e.message);
    } finally {
      $("btnActivateNow").disabled = false;
      $("btnActivateNow").textContent = prev || "Activate";
    }
  }

  // Wire UI
  $("btnVerify").addEventListener("click", () => {
    setMErr(""); setMOk("");
    $("mCode").value = "";
    openModal();
  });

  $("btnClose").addEventListener("click", closeModal);
  $("backdrop").addEventListener("click", (e) => {
    if (e.target?.id === "backdrop") closeModal();
  });

  $("btnSendCode").addEventListener("click", () => sendCode());
  $("btnVerifyCode").addEventListener("click", () => verifyCode());

  $("btnShowActivate").addEventListener("click", () => {
    if (verified) $("activateBox").style.display = "block";
  });

  $("btnActivateNow").addEventListener("click", () => activate());

  // Init
  loadInfo().catch((e) => setErr(e.message));
})();
