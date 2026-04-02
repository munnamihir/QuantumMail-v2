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

    await pool.query(
      `
      INSERT INTO qm_devices (user_id, device_id, label, device_type, pub_jwk, status)
      VALUES ($1,$2,$3,$4,$5,'pending')
      ON CONFLICT (user_id, device_id)
      DO UPDATE SET
        pub_jwk = EXCLUDED.pub_jwk,
        label = EXCLUDED.label,
        device_type = EXCLUDED.device_type,
        status = 'pending'
      `,
      [userId, device_id, label, device_type, pub_jwk]
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
    const { device_id } = req.body;

    // ✅ activate device
    await pool.query(
      `
      UPDATE qm_devices
      SET status = 'active'
      WHERE user_id = $1 AND device_id = $2
      `,
      [userId, device_id]
    );

    /* =========================
       🔐 ENSURE VAULT EXISTS
    ========================= */
    const { rows } = await pool.query(
      `SELECT user_id FROM qm_recovery_vault WHERE user_id=$1`,
      [userId]
    );

    if (!rows.length) {
      console.log("🔐 Creating vault for user:", userId);

      await pool.query(
        `
        INSERT INTO qm_recovery_vault
        (user_id, token_id, token_verifier_hash, enc_wk_b64, iv_b64)
        VALUES ($1, $2, $3, $4, $5)
        `,
        [
          userId,
          crypto.randomUUID(),
          crypto.createHash("sha256").update(userId).digest("hex"),
          "TEMP_KEY",   // later: encrypted private key
          "TEMP_IV"
        ]
      );
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

    await pool.query(
      `
      UPDATE qm_devices
      SET status = 'revoked'
      WHERE user_id = $1 AND device_id = $2
      `,
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
      `
      SELECT device_id, label, device_type, pub_jwk, status
      FROM qm_devices
      WHERE user_id = $1
      ORDER BY device_id DESC
      `,
      [userId]
    );

    res.json({
     devices: rows.map(r => ({
       device_id: r.device_id,
       label: r.label,
       device_type: r.device_type,
       pub_jwk: r.pub_jwk,
       status: r.revoked ? "revoked" : (r.status || "pending")
     }))
   });
  } catch (e) {
    console.error("LIST ERROR:", e);
    res.status(500).json({ error: "device_list_failed" });
  }
});
