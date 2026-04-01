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
  const approverDevice = req.headers["x-qm-device-id"];
  const { request_id, encrypted_private_key } = req.body;

  // ❗ prevent self-approval
  const { rows: reqRows } = await pool.query(`
    SELECT requester_device_id
    FROM qm_recovery_requests
    WHERE request_id=$1 AND user_id=$2
  `, [request_id, userId]);

  if (!reqRows.length) {
    return res.status(404).json({ error: "Request not found" });
  }

  if (reqRows[0].requester_device_id === approverDevice) {
    return res.status(400).json({ error: "Requester cannot approve" });
  }

  // ✅ insert approval
  await pool.query(`
    INSERT INTO qm_recovery_approvals
    (request_id, user_id, device_id, sig_b64)
    VALUES ($1,$2,$3,$4)
    ON CONFLICT DO NOTHING
  `, [request_id, userId, approverDevice, encrypted_private_key]);

  // ✅ count approvals
  const { rows } = await pool.query(`
    SELECT COUNT(*) as count
    FROM qm_recovery_approvals
    WHERE request_id=$1
  `, [request_id]);

  const approvals = Number(rows[0].count);

  // 🔥 quorum condition
  if (approvals >= 2) {
    await pool.query(`
      UPDATE qm_recovery_requests
      SET status='approved', approved_at=now()
      WHERE request_id=$1
    `, [request_id]);
  }

  res.json({
    ok: true,
    approvals,
    required: 2,
    status: approvals >= 2 ? "approved" : "pending"
  });
});

/* =========================
   FINISH RECOVERY
========================= */
recoveryDeviceRoutes.get("/finish/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const userId = req.qm.user.userId;

  const { rows } = await pool.query(`
    SELECT status
    FROM qm_recovery_requests
    WHERE request_id=$1 AND user_id=$2
  `, [id, userId]);

  const r = rows[0];

  if (!r || r.status !== "approved") {
    return res.status(400).json({
      error: "Quorum not reached (need 2 devices)"
    });
  }

  // 🔥 latest approval key
  const { rows: approvals } = await pool.query(`
    SELECT sig_b64
    FROM qm_recovery_approvals
    WHERE request_id=$1
    ORDER BY approved_at DESC
    LIMIT 1
  `, [id]);

  res.json({
    encrypted_key: approvals[0].sig_b64
  });
});
