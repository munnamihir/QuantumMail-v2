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
  const tokenId = crypto.randomBytes(16).toString("hex");

   await pool.query(`
     INSERT INTO qm_recovery_requests
     (request_id, user_id, token_id, requester_device_id, nonce_b64, status)
     VALUES ($1,$2,$3,$4,$5,'pending')
   `, [requestId, userId, tokenId, requesterDevice, nonce]);

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
deviceRoutes.post("/approve", requireAuth, async (req, res) => {
  try {
    const userId = req.qm.user.userId;
    const approverDeviceId = req.headers["x-qm-device-id"];

    const { request_id } = req.body;

    if (!request_id) {
      return res.status(400).json({ error: "request_id required" });
    }

    if (!approverDeviceId) {
      return res.status(400).json({ error: "missing device id header" });
    }

    const { rows } = await pool.query(
      `SELECT * FROM qm_recovery_requests WHERE request_id = $1`,
      [request_id]
    );

    const reqRow = rows[0];

    if (!reqRow) {
      return res.status(404).json({ error: "request not found" });
    }

    if (reqRow.status !== "pending") {
      return res.json({ ok: true, status: reqRow.status });
    }

    // prevent self-approval
    if (reqRow.device_id === approverDeviceId) {
      return res.status(400).json({ error: "cannot approve your own request" });
    }

    // insert approval
    await pool.query(
      `
      INSERT INTO qm_recovery_approvals (request_id, device_id)
      VALUES ($1, $2)
      ON CONFLICT DO NOTHING
      `,
      [request_id, approverDeviceId]
    );

    // count approvals
    const { rows: approvals } = await pool.query(
      `SELECT COUNT(*) FROM qm_recovery_approvals WHERE request_id = $1`,
      [request_id]
    );

    const count = Number(approvals[0].count);

    // threshold = 2 (you can change)
    if (count >= 2) {
      await pool.query(
        `UPDATE qm_recovery_requests SET status = 'approved' WHERE request_id = $1`,
        [request_id]
      );
    }

    res.json({ ok: true, approvals: count });

  } catch (e) {
    console.error("APPROVE ERROR:", e);
    res.status(500).json({ error: "approve_failed" });
  }
});

/* =========================
   FINISH RECOVERY
========================= */
recoveryDeviceRoutes.get("/finish/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const userId = req.qm.user.userId;

  // 1. Check quorum
  const { rows } = await pool.query(`
    SELECT status
    FROM qm_recovery_requests
    WHERE request_id=$1 AND user_id=$2
  `, [id, userId]);

  if (!rows.length || rows[0].status !== "approved") {
    return res.status(400).json({ error: "Quorum not reached" });
  }

  // 2. Fetch vault (REAL recovery)
  const { rows: vault } = await pool.query(`
    SELECT enc_wk_b64, iv_b64, wk_version
    FROM qm_recovery_vault
    WHERE user_id=$1
  `, [userId]);

  if (!vault.length) {
    return res.status(404).json({ error: "Vault not found" });
  }

  res.json({
    ok: true,
    vault: vault[0]
  });
});
