import express from "express";
import crypto from "crypto";
import { pool } from "../db.js";
import { requireAuth } from "../server.js";

export const recoveryDeviceRoutes = express.Router();

/* =========================
   START RECOVERY
========================= */
recoveryDeviceRoutes.post("/start", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;
  const requesterDevice = req.headers["x-qm-device-id"];

  const requestId = crypto.randomBytes(16).toString("hex");
  const nonce = crypto.randomBytes(32).toString("base64");

  await pool.query(`
    INSERT INTO qm_recovery_requests
    (request_id, user_id, requester_device_id, nonce_b64, status)
    VALUES ($1,$2,$3,$4,'pending')
  `, [requestId, userId, requesterDevice, nonce]);

  res.json({
    request_id: requestId,
    nonce
  });
});

/* =========================
   LIST PENDING
========================= */
recoveryDeviceRoutes.get("/pending", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;

  const { rows } = await pool.query(`
    SELECT request_id, requester_device_id, nonce_b64, status
    FROM qm_recovery_requests
    WHERE user_id=$1 AND status='pending'
  `, [userId]);

  res.json({ pending: rows });
});

/* =========================
   APPROVE (QUORUM)
========================= */
recoveryDeviceRoutes.post("/approve", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;
  const deviceId = req.headers["x-qm-device-id"];
  const { request_id } = req.body;

  await pool.query(`
    INSERT INTO qm_recovery_approvals
    (request_id, user_id, device_id, sig_b64)
    VALUES ($1,$2,$3,$4)
    ON CONFLICT DO NOTHING
  `, [request_id, userId, deviceId, "approved"]);

  const { rows } = await pool.query(`
    SELECT COUNT(*) as count
    FROM qm_recovery_approvals
    WHERE request_id=$1
  `, [request_id]);

  const approvals = Number(rows[0].count);

  if (approvals >= 2) {
    await pool.query(`
      UPDATE qm_recovery_requests
      SET status='approved'
      WHERE request_id=$1
    `, [request_id]);
  }

  res.json({ ok: true, approvals });
});

/* =========================
   FINISH RECOVERY
========================= */
recoveryVaultRoutes.get("/finish/:id", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;

  const { rows } = await pool.query(`
    SELECT enc_wk_b64, iv_b64
    FROM qm_recovery_vault
    WHERE user_id=$1
  `, [userId]);

  if (!rows.length) {
    return res.status(404).json({ error: "Vault not found" });
  }

  res.json(rows[0]);
});
