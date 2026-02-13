// portal/analytics.js

const $ = (id) => document.getElementById(id);

let token = "";

function ok(msg){ $("ok").textContent = msg || ""; if (msg) $("err").textContent=""; }
function err(msg){ $("err").textContent = msg || ""; if (msg) $("ok").textContent=""; }

async function api(path) {
  const res = await fetch(path, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

function countBy(items) {
  const m = new Map();
  for (const it of items || []) {
    const k = String(it.action || "unknown");
    m.set(k, (m.get(k) || 0) + 1);
  }
  return Array.from(m.entries()).sort((a,b)=>b[1]-a[1]);
}

function renderActionCounts(pairs) {
  const tb = $("actionsTbody");
  if (!tb) return;

  if (!pairs.length) {
    tb.innerHTML = `<tr><td colspan="2" class="muted">No data.</td></tr>`;
    return;
  }

  tb.innerHTML = pairs.map(([action, c]) => `
    <tr>
      <td><code>${escapeHtml(action)}</code></td>
      <td><b>${c}</b></td>
    </tr>
  `).join("");
}

function renderRecent(items) {
  const tb = $("recentTbody");
  if (!tb) return;

  const list = (items || []).slice(0, 30);
  if (!list.length) {
    tb.innerHTML = `<tr><td colspan="4" class="muted">No data.</td></tr>`;
    return;
  }

  tb.innerHTML = list.map((it) => {
    const at = escapeHtml(it.at || "");
    const userId = escapeHtml(it.userId || "—");
    const action = escapeHtml(it.action || "");
    const info = escapeHtml(compactInfo(it));
    return `
      <tr>
        <td>${at}</td>
        <td><code>${userId}</code></td>
        <td><b>${action}</b></td>
        <td class="muted">${info}</td>
      </tr>
    `;
  }).join("");
}

function compactInfo(it) {
  const clone = { ...it };
  delete clone.at; delete clone.userId; delete clone.orgId; delete clone.action; delete clone.id;
  delete clone.ip; delete clone.ua;
  const s = JSON.stringify(clone);
  return s.length > 180 ? s.slice(0, 180) + "…" : s;
}

function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

async function refresh() {
  ok(""); err("");

  if (!token) {
    token = prompt("Paste Admin Bearer token (from /auth/login response):") || "";
    token = token.trim();
  }
  if (!token) return err("Token required.");

  try {
    const out = await api("/admin/audit?limit=500");
    const items = out.items || [];

    const pairs = countBy(items);

    const getCount = (action) => (pairs.find(([a]) => a === action)?.[1] || 0);

    $("kpiLogins").textContent = String(getCount("login"));
    $("kpiEncrypts").textContent = String(getCount("encrypt_store"));
    $("kpiDecrypts").textContent = String(getCount("decrypt_payload"));
    $("kpiDenied").textContent = String(getCount("decrypt_denied"));
    $("kpiKeys").textContent = String(getCount("pubkey_register"));
    $("kpiRotations").textContent = String(getCount("kek_rotate"));

    renderActionCounts(pairs.slice(0, 12));
    renderRecent(items);

    ok(`Loaded ${items.length} audit items.`);
  } catch (e) {
    err(e?.message || String(e));
  }
}

$("btnBack")?.addEventListener("click", () => {
  window.location.href = "/portal/admin.html";
});

$("btnRefresh")?.addEventListener("click", refresh);

// auto-load once
refresh();
