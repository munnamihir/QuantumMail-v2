// server/routes/recoveryVault.js
import express from "express";
import crypto from "crypto";
import { pool } from "../db.js";
import { requireAuth } from "../server.js";

export const recoveryVaultRoutes = express.Router();


recoveryVaultRoutes.post("/init", requireAuth, async (req, res) => {
  try {
    const userId = req.qm.user.userId;
    const token_id = "rrt_" + crypto.randomBytes(16).toString("hex");

    // Store the token_id temporarily so we can verify it on PUT /vault
    await pool.query(
      `INSERT INTO qm_recovery_vault
         (user_id, token_id, token_verifier_hash, enc_wk_b64, iv_b64, wk_version, updated_at)
       VALUES ($1, $2, 'pending', 'pending', 'pending', 2, now())
       ON CONFLICT (user_id) DO UPDATE SET
         token_id = excluded.token_id,
         updated_at = now()`,
      [userId, token_id]
    );

    res.json({ ok: true, token_id });
  } catch (e) {
    console.error("POST /api/recovery/init failed:", e);
    res.status(500).json({ error: "init_failed" });
  }
});

recoveryVaultRoutes.put("/vault", requireAuth, async (req, res) => {
  try {
    const userId = req.qm.user.userId;
    const {
      token_id,
      token_verifier_hash,
      enc_wk_b64,
      iv_b64,
      wk_version
    } = req.body || {};

    if (!token_id || !token_verifier_hash || !enc_wk_b64 || !iv_b64) {
      return res.status(400).json({ error: "missing_fields" });
    }

    // Reject placeholder values from TEMP_KEY era
    if (
      enc_wk_b64 === "TEMP_KEY" ||
      iv_b64 === "TEMP_IV" ||
      iv_b64 === "iv_placeholder" ||
      token_verifier_hash === "pending"
    ) {
      return res.status(400).json({ error: "invalid_vault_content" });
    }

    // Validate wk_version
    const version = Number.isInteger(wk_version) && wk_version > 0 ? wk_version : 2;

    // Check if vault exists with real data — if so require token_id to match
    const { rows: existing } = await pool.query(
      `SELECT token_id, token_verifier_hash FROM qm_recovery_vault WHERE user_id = $1`,
      [userId]
    );

    if (existing.length && existing[0].token_verifier_hash !== "pending") {
      // Vault already has real data — verify token_id matches what was issued by /init
      try {
        const match = crypto.timingSafeEqual(
          Buffer.from(String(existing[0].token_id)),
          Buffer.from(String(token_id))
        );
        if (!match) return res.status(403).json({ error: "token_id_mismatch" });
      } catch {
        return res.status(403).json({ error: "token_id_mismatch" });
      }
    }

    const { rows } = await pool.query(`
      INSERT INTO qm_recovery_vault
        (user_id, token_id, token_verifier_hash, enc_wk_b64, iv_b64, wk_version, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6, now())
      ON CONFLICT (user_id) DO UPDATE SET
        token_id = excluded.token_id,
        token_verifier_hash = excluded.token_verifier_hash,
        enc_wk_b64 = excluded.enc_wk_b64,
        iv_b64 = excluded.iv_b64,
        wk_version = excluded.wk_version,
        updated_at = now()
      RETURNING user_id, token_id, wk_version, updated_at
    `, [userId, String(token_id), String(token_verifier_hash), String(enc_wk_b64), String(iv_b64), version]);

    res.json({ ok: true, vault: rows[0] });
  } catch (e) {
    console.error("PUT /api/recovery/vault failed:", e);
    res.status(500).json({ error: "vault_write_failed" });
  }
});

recoveryVaultRoutes.get("/vault", requireAuth, async (req, res) => {
  try {
    const userId = req.qm.user.userId;

    const { rows } = await pool.query(
      `select user_id, token_id, enc_wk_b64, iv_b64, wk_version, updated_at
         from qm_recovery_vault
        where user_id = $1`,
      [userId]
    );

    if (!rows.length) return res.status(404).json({ error: "vault_not_found" });
    res.json({ ok: true, vault: rows[0] });
  } catch (e) {
    console.error("GET /api/recovery/vault failed:", e);
    res.status(500).json({ error: "vault_read_failed", detail: String(e?.message || e) });
  }
});
