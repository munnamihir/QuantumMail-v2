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
    (request_id, user_id, requester_device_id, nonce, status)
    VALUES ($1,$2,$3,$4,'pending')
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
   APPROVE RECOVERY
========================= */
recoveryDeviceRoutes.post("/approve", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;
  const approverDevice = req.headers["x-qm-device-id"];
  const { request_id, encrypted_private_key } = req.body;

  await pool.query(`
    UPDATE qm_recovery_requests
    SET status='approved',
        approved_by=$1,
        encrypted_key=$2
    WHERE request_id=$3 AND user_id=$4
  `, [approverDevice, encrypted_private_key, request_id, userId]);

  res.json({ ok: true });
});

/* =========================
   FINISH RECOVERY
========================= */
recoveryDeviceRoutes.get("/finish/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const userId = req.qm.user.userId;

  const { rows } = await pool.query(`
    SELECT encrypted_key, status
    FROM qm_recovery_requests
    WHERE request_id=$1 AND user_id=$2
  `, [id, userId]);

  const r = rows[0];

  if (!r || r.status !== "approved") {
    return res.status(400).json({ error: "Not approved yet" });
  }

  res.json({
    encrypted_key: r.encrypted_key
  });
});
