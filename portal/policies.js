const $ = (id) => document.getElementById(id);
let token = sessionStorage.getItem("qm_admin_token") || "";

async function api(path, { method="GET", body=null } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

function setOk(msg){ $("ok").textContent = msg || ""; }
function setErr(msg){ $("err").textContent = msg || ""; }

async function load() {
  setOk(""); setErr("");
  if (!token) throw new Error("No admin token. Login on Admin page first.");
  const out = await api("/admin/policies");
  const p = out.policies || {};
  $("forceAttachmentEncryption").checked = !!p.forceAttachmentEncryption;
  $("disablePassphraseMode").checked = !!p.disablePassphraseMode;
  $("requireReauthForDecrypt").checked = !!p.requireReauthForDecrypt;
  $("enforceKeyRotationDays").value = String(p.enforceKeyRotationDays || 0);
  setOk("Loaded ✅");
}

async function save() {
  setOk(""); setErr("");
  if (!token) throw new Error("No admin token. Login on Admin page first.");

  const body = {
    forceAttachmentEncryption: $("forceAttachmentEncryption").checked,
    disablePassphraseMode: $("disablePassphraseMode").checked,
    requireReauthForDecrypt: $("requireReauthForDecrypt").checked,
    enforceKeyRotationDays: parseInt($("enforceKeyRotationDays").value || "0", 10) || 0
  };

  const out = await api("/admin/policies", { method:"POST", body });
  setOk(`Saved ✅\n${JSON.stringify(out.policies, null, 2)}`);
}

$("btnLoad").addEventListener("click", () => load().catch(e => setErr(e.message)));
$("btnSave").addEventListener("click", () => save().catch(e => setErr(e.message)));

load().catch(() => {});
