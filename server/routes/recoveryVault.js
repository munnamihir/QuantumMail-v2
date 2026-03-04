import express from "express";
import crypto from "crypto";
import { pool } from "../db.js";

export const recoveryVaultRoutes = express.Router();

// Replace this with your real auth middleware
function requireAuth(req, res, next) {
  // Example: req.user = { user_id: "u_abc" }
  if (!req.user?.user_id) return res.status(401).json({ error: "unauthorized" });
  next();
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s), "utf8").digest("hex");
}

/**
 * POST /api/recovery/init
 * Generates a token_id (public). Token secret is generated client-side.
 */
recoveryVaultRoutes.post("/init", requireAuth, async (req, res) => {
  const userId = req.user.user_id;
  const token_id = "rrt_" + crypto.randomBytes(6).toString("hex"); // short public id
  res.json({ token_id });
});

/**
 * PUT /api/recovery/vault
 * Saves the encrypted WK vault blob.
 */
recoveryVaultRoutes.put("/vault", requireAuth, async (req, res) => {
  const userId = req.user.user_id;

  const {
    token_id,
    token_verifier_hash,
    enc_wk_b64,
    iv_b64,
    tag_b64,
    wk_version
  } = req.body || {};

  if (!token_id || !token_verifier_hash || !enc_wk_b64 || !iv_b64 || !tag_b64) {
    return res.status(400).json({ error: "missing_fields" });
  }

  // Basic shape checks
  if (String(token_verifier_hash).length < 32) return res.status(400).json({ error: "bad_verifier" });

  const q = `
    insert into qm_recovery_vault
      (user_id, token_id, token_verifier_hash, enc_wk_b64, iv_b64, tag_b64, wk_version, updated_at)
    values
      ($1,$2,$3,$4,$5,$6,$7, now())
    on conflict (user_id) do update set
      token_id = excluded.token_id,
      token_verifier_hash = excluded.token_verifier_hash,
      enc_wk_b64 = excluded.enc_wk_b64,
      iv_b64 = excluded.iv_b64,
      tag_b64 = excluded.tag_b64,
      wk_version = excluded.wk_version,
      updated_at = now()
    returning user_id, token_id, wk_version, updated_at
  `;
  const vals = [userId, token_id, token_verifier_hash, enc_wk_b64, iv_b64, tag_b64, Number(wk_version || 1)];

  const { rows } = await pool.query(q, vals);
  res.json({ ok: true, vault: rows[0] });
});

/**
 * GET /api/recovery/vault
 * Returns the encrypted vault blob to the authenticated user.
 */
recoveryVaultRoutes.get("/vault", requireAuth, async (req, res) => {
  const userId = req.user.user_id;

  const { rows } = await pool.query(
    `select user_id, token_id, enc_wk_b64, iv_b64, tag_b64, kdf, cipher, wk_version, updated_at
     from qm_recovery_vault where user_id=$1`,
    [userId]
  );

  if (!rows.length) return res.status(404).json({ error: "vault_not_found" });
  res.json(rows[0]);
});
