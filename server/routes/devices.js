import express from "express";
import { pool } from "../db.js";
import { requireAuth } from "../server.js";
import crypto from "crypto";

export const deviceRoutes = express.Router();

/* =========================
   REGISTER (PENDING ONLY)
========================= */
deviceRoutes.post("/register", requireAuth, async (req, res) => {
  try {
    const userId = req.qm.user.userId;
    const { device_id, label, device_type, pub_jwk } = req.body;

    if (!device_id || !pub_jwk) {
      return res.status(400).json({ error: "device_id and pub_jwk required" });
    }

    // Validate pub_jwk is an Ed25519 public key — no private key material
    if (typeof pub_jwk !== "object" || pub_jwk === null) {
      return res.status(400).json({ error: "pub_jwk must be a JWK object" });
    }
    // Accept RSA-OAEP (extension) or Ed25519 (recovery quorum) public keys
    // Reject anything with private key material
    if (pub_jwk.kty === "RSA") {
      // RSA public key — must not have private key material (d component)
      if (!pub_jwk.n || !pub_jwk.e || pub_jwk.d) {
        return res.status(400).json({ error: "Invalid RSA public key" });
      }
    } else if (pub_jwk.kty === "OKP") {
      // Ed25519 public key — must not have private key material (d component)
      if (!pub_jwk.x || pub_jwk.d) {
        return res.status(400).json({ error: "Invalid Ed25519 public key" });
      }
    } else {
      return res.status(400).json({ error: "pub_jwk must be an RSA or Ed25519 public key" });
    }

    await pool.query(
      `INSERT INTO qm_devices (user_id, device_id, label, device_type, pub_jwk, status)
       VALUES ($1,$2,$3,$4,$5::jsonb,'pending')
       ON CONFLICT (user_id, device_id)
       DO UPDATE SET
         pub_jwk = EXCLUDED.pub_jwk,
         label = EXCLUDED.label,
         device_type = EXCLUDED.device_type,
         status = 'pending'`,
      [userId, device_id, label || "", device_type || "desktop", JSON.stringify(pub_jwk)]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error("REGISTER ERROR:", e);
    res.status(500).json({ error: "device_register_failed" });
  }
});

/* =========================
   TRUST DEVICE
========================= */
deviceRoutes.post("/trust", requireAuth, async (req, res) => {
  try {
    const userId = req.qm.user.userId;
    const { device_id, label, token_id, token_verifier_hash, enc_wk_b64, iv_b64 } = req.body;

    if (!device_id) return res.status(400).json({ error: "device_id required" });

    // Verify device exists and is pending
    const { rows: devRows } = await pool.query(
      `SELECT status FROM qm_devices WHERE user_id = $1 AND device_id = $2`,
      [userId, device_id]
    );
    if (!devRows.length) return res.status(404).json({ error: "device_not_found" });
    if (devRows[0].status === "active") return res.json({ ok: true }); // idempotent

    await pool.query(
      `UPDATE qm_devices
       SET status = 'active', label = COALESCE($3, label)
       WHERE user_id = $1 AND device_id = $2`,
      [userId, device_id, label]
    );

    // Only create vault if real encrypted key data is provided
    if (token_id && token_verifier_hash && enc_wk_b64 && iv_b64) {
      if (enc_wk_b64 !== "TEMP_KEY" && iv_b64 !== "TEMP_IV" && iv_b64 !== "iv_placeholder") {
        await pool.query(
          `INSERT INTO qm_recovery_vault
             (user_id, token_id, token_verifier_hash, enc_wk_b64, iv_b64, wk_version, updated_at)
           VALUES ($1, $2, $3, $4, $5, 2, now())
           ON CONFLICT (user_id) DO UPDATE SET
             token_id = excluded.token_id,
             token_verifier_hash = excluded.token_verifier_hash,
             enc_wk_b64 = excluded.enc_wk_b64,
             iv_b64 = excluded.iv_b64,
             updated_at = now()`,
          [userId, token_id, token_verifier_hash, enc_wk_b64, iv_b64]
        );
      }
    }

    res.json({ ok: true });
  } catch (e) {
    console.error("TRUST ERROR:", e);
    res.status(500).json({ error: "device_trust_failed" });
  }
});

/* =========================
   REVOKE DEVICE
========================= */
deviceRoutes.post("/revoke", requireAuth, async (req, res) => {
  try {
    const userId = req.qm.user.userId;
    const { device_id } = req.body;

    if (!device_id) return res.status(400).json({ error: "device_id required" });

    await pool.query(
      `UPDATE qm_devices
       SET status = 'revoked', revoked = true
       WHERE user_id = $1 AND device_id = $2`,
      [userId, device_id]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error("REVOKE ERROR:", e);
    res.status(500).json({ error: "device_revoke_failed" });
  }
});

/* =========================
   LIST DEVICES
========================= */
deviceRoutes.get("/list", requireAuth, async (req, res) => {
  try {
    const userId = req.qm.user.userId;
    const { rows } = await pool.query(
      `SELECT device_id, label, device_type, pub_jwk, status, revoked, created_at
       FROM qm_devices
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [userId]
    );
    res.json({
      devices: rows.map(r => ({
        device_id: r.device_id,
        label: r.label,
        device_type: r.device_type,
        pub_jwk: r.pub_jwk,
        status: r.revoked ? "revoked" : (r.status || "pending"),
        createdAt: r.created_at
      }))
    });
  } catch (e) {
    console.error("LIST ERROR:", e);
    res.status(500).json({ error: "device_list_failed" });
  }
});
