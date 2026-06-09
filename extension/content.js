// extension/content.js
// Gmail-safe selection caching + replace selection + decrypt bridge

console.log("🔥 QuantumMail content.js injected");

/* =========================
   SELECTION CACHE
========================= */

let cachedSelectionText = "";
let cachedRange = null;
let lastActiveCompose = null;

function cloneRangeIfPossible(sel) {
  try {
    if (!sel || sel.rangeCount === 0) return null;
    return sel.getRangeAt(0).cloneRange();
  } catch {
    return null;
  }
}

function cacheSelectionNow() {
  try {
    const sel = window.getSelection?.();
    if (!sel) return;

    const text = String(sel.toString() || "").trim();
    if (text) cachedSelectionText = text;

    const r = cloneRangeIfPossible(sel);
    if (r && text) cachedRange = r;
  } catch {}
}

/* Track compose editor */
document.addEventListener("focusin", (e) => {
  const el = e.target;
  if (!el) return;

  if (el.isContentEditable || el.getAttribute?.("contenteditable") === "true") {
    lastActiveCompose = el;
  }
});

/* Cache aggressively (Gmail loses selection) */
document.addEventListener("pointerdown", cacheSelectionNow, true);
document.addEventListener("pointerup", cacheSelectionNow, true);
document.addEventListener("mouseup", cacheSelectionNow, true);
document.addEventListener("keyup", cacheSelectionNow, true);
document.addEventListener("selectionchange", cacheSelectionNow, true);

setInterval(cacheSelectionNow, 250);

function getSelectionTextRobust() {
  try {
    const live = String(window.getSelection?.()?.toString() || "").trim();
    if (live) return live;
  } catch {}

  return cachedSelectionText || "";
}

/* =========================
   REPLACE LOGIC
========================= */

function replaceUsingCachedRange(link) {
  try {
    if (!cachedRange) return false;

    const common = cachedRange.commonAncestorContainer;
    const containerEl =
      common?.nodeType === Node.ELEMENT_NODE ? common : common?.parentElement;

    if (!containerEl || !document.contains(containerEl)) return false;

    let cur = containerEl;
    let okEditable = false;

    while (cur && cur !== document.body) {
      if (cur.isContentEditable || cur.getAttribute?.("contenteditable") === "true") {
        okEditable = true;
        break;
      }
      cur = cur.parentElement;
    }

    if (!okEditable) return false;

    cachedRange.deleteContents();
    cachedRange.insertNode(document.createTextNode(link));

    cachedRange.collapse(false);

    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(cachedRange);

    cachedSelectionText = "";
    cachedRange = null;

    return true;
  } catch {
    return false;
  }
}

function replaceUsingExecCommand(link) {
  try {
    const ok = document.execCommand("insertText", false, link);
    if (ok) {
      cachedSelectionText = "";
      cachedRange = null;
    }
    return ok;
  } catch {
    return false;
  }
}

function insertFallback(link) {
  try {
    const editor =
      (document.activeElement?.isContentEditable && document.activeElement) ||
      lastActiveCompose ||
      document.querySelector('[role="textbox"][contenteditable="true"]');

    if (!editor) return false;

    editor.focus();
    document.execCommand("insertText", false, link);

    return true;
  } catch {
    return false;
  }
}

/* =========================
   EXTENSION MESSAGE HANDLER
========================= */

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {

      /* GET SELECTION */
      if (msg?.type === "QM_GET_SELECTION") {
        const text = getSelectionTextRobust();
        sendResponse({ ok: true, text });
        return;
      }

      /* REPLACE TEXT */
      if (msg?.type === "QM_REPLACE_SELECTION_WITH_LINK") {
        const url = String(msg.url || "").trim();
        if (!url) {
          sendResponse({ ok: false, error: "Missing url" });
          return;
        }

        if (replaceUsingExecCommand(url)) {
          sendResponse({ ok: true });
          return;
        }

        if (replaceUsingCachedRange(url)) {
          sendResponse({ ok: true });
          return;
        }

        if (insertFallback(url)) {
          sendResponse({
            ok: true,
            warning: "Inserted link but could not replace selection"
          });
          return;
        }

        sendResponse({
          ok: false,
          error: "Select text in compose body first"
        });
        return;
      }

      /* PING */
      if (msg?.type === "QM_PING") {
        sendResponse({ ok: true });
        return;
      }

      sendResponse({ ok: false, error: "Unknown message" });

    } catch (e) {
      sendResponse({ ok: false, error: e?.message || String(e) });
    }
  })();

  return true;
});

/* =========================
   DECRYPT BRIDGE (/m/<id>)
========================= */

function getMsgIdFromPath() {
  const parts = location.pathname.split("/").filter(Boolean);
  if (parts[0] === "m" && parts[1]) return parts[1];
  return null;
}

console.log("QuantumMail decrypt bridge active on:", location.pathname);

window.addEventListener("message", (event) => {
  const data = event.data || {};

  if (data?.source !== "quantummail-portal") return;
  if (data?.type !== "QM_LOGIN_AND_DECRYPT_REQUEST") return;

  console.log("📩 CONTENT: decrypt request received", data);

  const msgId = data.msgId || getMsgIdFromPath();

  chrome.runtime.sendMessage(
    {
      type: "QM_LOGIN_AND_DECRYPT",
      msgId,
      serverBase: data.serverBase,
      orgId: data.orgId,
      username: data.username,
      password: data.password
    },
    (resp) => {

      /* 🔥 CRITICAL FIX */
      if (chrome.runtime.lastError) {
        console.error("🚨 EXTENSION ERROR:", chrome.runtime.lastError.message);

        window.postMessage(
          {
            source: "quantummail-extension",
            type: "QM_DECRYPT_RESULT",
            ok: false,
            error: chrome.runtime.lastError.message
          },
          "*"
        );
        return;
      }

      if (!resp) {
        window.postMessage(
          {
            source: "quantummail-extension",
            type: "QM_DECRYPT_RESULT",
            ok: false,
            error: "No response from extension"
          },
          "*"
        );
        return;
      }

      console.log("✅ CONTENT: response from background", resp);

      const out = resp.ok
        ? {
            source: "quantummail-extension",
            type: "QM_DECRYPT_RESULT",
            ok: true,
            plaintext: resp.plaintext,
            attachments: resp.attachments || [],
            message: "Decrypted ✅ (access audited)"
          }
        : {
            source: "quantummail-extension",
            type: "QM_DECRYPT_RESULT",
            ok: false,
            error: resp.error || "Decrypt failed"
          };

      window.postMessage(out, "*");
    }
  );
});
