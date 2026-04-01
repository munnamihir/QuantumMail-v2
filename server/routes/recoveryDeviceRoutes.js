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
  const deviceId = req.headers["x-qm-device-id"];

  const requestId = crypto.randomBytes(16).toString("hex");
  const nonce = crypto.randomBytes(16).toString("base64");

  await pool.query(`
    INSERT INTO qm_recovery_requests
    (request_id, user_id, requester_device_id, nonce, status, required_approvals)
    VALUES ($1,$2,$3,$4,'pending', 2)
  `, [requestId, userId, deviceId, nonce]);

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
    SELECT request_id, requester_device_id, nonce
    FROM qm_recovery_requests
    WHERE user_id=$1 AND status='pending'
  `, [userId]);

  res.json({ pending: rows });
});

/* =========================
   APPROVE RECOVERY (QUORUM)
========================= */
recoveryDeviceRoutes.post("/approve", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;
  const approverDevice = req.headers["x-qm-device-id"];
  const { request_id, encrypted_private_key } = req.body;

  /* ✅ Check device is active */
  const { rows: devices } = await pool.query(`
    SELECT * FROM qm_devices
    WHERE user_id=$1 AND device_id=$2 AND status='active' AND revoked=false
  `, [userId, approverDevice]);

  if (!devices.length) {
    return res.status(403).json({ error: "Device not trusted" });
  }

  /* ✅ Insert approval (no duplicates) */
  await pool.query(`
    INSERT INTO qm_recovery_approvals (request_id, device_id)
    VALUES ($1,$2)
    ON CONFLICT DO NOTHING
  `, [request_id, approverDevice]);

  /* ✅ Count approvals */
  const { rows: countRows } = await pool.query(`
    SELECT COUNT(*) FROM qm_recovery_approvals
    WHERE request_id=$1
  `, [request_id]);

  const approvals = Number(countRows[0].count);

  /* ✅ Get required approvals */
  const { rows: reqRows } = await pool.query(`
    SELECT required_approvals
    FROM qm_recovery_requests
    WHERE request_id=$1 AND user_id=$2
  `, [request_id, userId]);

  if (!reqRows.length) {
    return res.status(404).json({ error: "Request not found" });
  }

  const required = reqRows[0].required_approvals;

  /* ✅ If quorum reached → approve */
  if (approvals >= required) {
    await pool.query(`
      UPDATE qm_recovery_requests
      SET status='approved',
          encrypted_key=$1
      WHERE request_id=$2 AND user_id=$3
    `, [encrypted_private_key, request_id, userId]);
  }

  res.json({
    ok: true,
    approvals,
    required,
    remaining: Math.max(required - approvals, 0)
  });
});

/* =========================
   FINISH RECOVERY
========================= */
recoveryDeviceRoutes.get("/finish/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const userId = req.qm.user.userId;
  const deviceId = req.headers["x-qm-device-id"];

  const { rows } = await pool.query(`
    SELECT encrypted_key, status
    FROM qm_recovery_requests
    WHERE request_id=$1 AND user_id=$2
  `, [id, userId]);

  const r = rows[0];

  if (!r || r.status !== "approved") {
    return res.status(400).json({ error: "Not enough approvals yet" });
  }

  /* ✅ Activate new device */
  await pool.query(`
    UPDATE qm_devices
    SET status='active'
    WHERE device_id=$1 AND user_id=$2
  `, [deviceId, userId]);

  /* ✅ Mark completed */
  await pool.query(`
    UPDATE qm_recovery_requests
    SET status='completed'
    WHERE request_id=$1
  `, [id]);

  res.json({
    encrypted_key: r.encrypted_key
  });
});
