const $ = (id) => document.getElementById(id);
function ok(id, msg){ const el=$(id); if(el) el.textContent = msg||""; }
function err(id, msg){ const el=$(id); if(el) el.textContent = msg||""; }

function getAdminToken(){ return sessionStorage.getItem("qm_admin_token") || ""; }
async function api(path, { method="GET", body=null } = {}) {
  const token = getAdminToken();
  if (!token) throw new Error("Not logged in (admin).");
  const headers = { Authorization: `Bearer ${token}` };
  if (body) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(()=>({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

function setSlots(text) {
  // text format: "123-456" or "------"
  const parts = text.split("-");
  // for display we want 5 boxes; construct compact string of 6 digits or placeholders
  const compact = (parts.join("") || "").padEnd(6, "-");
  for (let i=0;i<5;i++){
    const el = $(`slot${i+1}`);
    if (!el) continue;
    // show groups: [0..2], [3..5] we have only 5 slots so we break 6 into five visual slots:
    // simplistic: show first 3 digits in first 3 slots, last 3 in next two slots split 3/2
    // but easier: show compact chars in the 5 slots (we'll show first 5 chars, then last char appended to slot5)
    const s = compact[i] || "-";
    el.textContent = s;
  }
  // append last char to slot5 visually (so 5 slots display 6th char small)
  const slot5 = $("slot5");
  if (slot5) slot5.textContent = compact.slice(4,6);
}

function animateTo(finalCode) {
  // finalCode e.g. "493-118" -> compact "493118"
  const compact = finalCode.replace(/-/g, "").padEnd(6, "-");
  // quick animation: spin random digits, then reveal target
  const duration = 1200;
  const start = Date.now();
  const tick = () => {
    const now = Date.now();
    const progress = Math.min(1, (now - start) / duration);
    if (progress < 0.9) {
      // show random digits
      const rnd = Array.from({length:6}, () => String(Math.floor(Math.random()*10)));
      // map into 5 slots: first 5 digits (last char grouped into slot5)
      for (let i=0;i<5;i++){
        const el = $(`slot${i+1}`);
        if (!el) continue;
        if (i < 4) el.textContent = rnd[i];
        else el.textContent = rnd[4] + rnd[5];
      }
      requestAnimationFrame(tick);
    } else {
      // reveal final
      const d = compact;
      for (let i=0;i<5;i++){
        const el = $(`slot${i+1}`);
        if (!el) continue;
        if (i < 4) el.textContent = d[i];
        else el.textContent = d.slice(4,6);
      }
    }
  };
  requestAnimationFrame(tick);
}

async function generateInvite() {
  ok("invOk",""); err("invErr","");
  const role = String($("selRole").value || "Member");
  const expires = Number($("expiresMinutes").value) || 60;
  try {
    const out = await api("/admin/invites/generate", { method: "POST", body: { role, expiresMinutes: expires } });
    const code = out.code;
    animateTo(code);
    $("btnCopy").style.display = "";
    $("btnCopy").dataset.code = code;
    $("generatedNote").textContent = `Code ${code} • expires ${new Date(out.expiresAt).toLocaleString()}`;
    ok("invOk", "Invite generated ✅");
    await refreshRecent();
  } catch (e) {
    err("invErr", e.message || String(e));
  }
}

async function refreshRecent() {
  ok("invOk",""); err("invErr","");
  try {
    const out = await api("/admin/invites");
    const items = Array.isArray(out.items) ? out.items : [];
    const container = $("recentContainer");
    if (!container) return;
    if (!items.length) {
      container.innerHTML = `<div class="muted">No invites generated yet.</div>`;
      return;
    }

    container.innerHTML = items.map(i => {
      const used = i.usedAt ? `<span style="color:var(--muted)">used</span>` : `<b>unused</b>`;
      return `<div class="invRow">
        <div>
          <div><b>${i.code}</b> <span class="invMeta">• ${i.role}</span></div>
          <div class="invMeta">created ${new Date(i.createdAt).toLocaleString()} • expires ${new Date(i.expiresAt).toLocaleString()}</div>
        </div>
        <div style="display:flex; gap:8px; align-items:center;">
          <button class="small" data-copy="${i.code}">Copy</button>
          ${i.usedAt ? `<div class="invMeta">Used: ${new Date(i.usedAt).toLocaleString()}</div>` : `<div class="invMeta">${used}</div>`}
        </div>
      </div>`;
    }).join("");

    // wire copy buttons
    container.querySelectorAll("button[data-copy]").forEach(b => {
      b.addEventListener("click", async (ev) => {
        const c = b.getAttribute("data-copy");
        try {
          await navigator.clipboard.writeText(c);
          ok("invOk", "Copied to clipboard ✅");
        } catch {
          err("invErr", "Copy failed — please select and copy manually.");
        }
      });
    });

  } catch (e) {
    err("invErr", e.message || String(e));
  }
}

(function init(){
  // ensure admin token exists
  const token = getAdminToken();
  if (!token) {
    // redirect to admin login
    window.location.href = "/portal/admin.html";
    return;
  }

  // init empty slots
  setSlots("------");
  $("btnGenerate").addEventListener("click", () => generateInvite());
  $("btnRefresh").addEventListener("click", () => refreshRecent().catch(e => err("invErr", e.message)));
  $("btnCopy").addEventListener("click", async () => {
    const code = $("btnCopy").dataset.code;
    if (!code) return;
    try {
      await navigator.clipboard.writeText(code);
      ok("invOk", "Copied to clipboard ✅");
    } catch {
      err("invErr", "Copy failed — please copy manually.");
    }
  });

  // logout
  $("btnLogout").addEventListener("click", () => {
    sessionStorage.removeItem("qm_admin_token");
    window.location.href = "/portal/admin.html";
  });

  refreshRecent().catch(()=>{ /* ignore */ });
})();
