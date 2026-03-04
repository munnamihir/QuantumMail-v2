import { setupRecoveryVault, recoverWrapKeyFromVault } from "./qmVault.js";

function reply(type, payload) {
  window.postMessage({ source: "qm-ext", type, payload }, "*");
}

window.addEventListener("message", async (event) => {
  const msg = event.data;
  if (!msg || msg.source !== "qm-portal") return;

  try {
    // you already store apiBase/org in extension storage; use your existing logic
    const apiBase = await getApiBaseSomehow(); // replace with your existing helper

    if (msg.type === "enable_vault") {
      const out = await setupRecoveryVault(apiBase);
      reply("vault_enabled", { token_display: out.display });
    }

    if (msg.type === "recover_vault") {
      await recoverWrapKeyFromVault(apiBase, msg.payload.token);
      reply("vault_recovered", {});
    }
  } catch (e) {
    reply("vault_error", { error: String(e?.message || e) });
  }
});
