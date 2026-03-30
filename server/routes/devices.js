import express from "express";
import { pool } from "../db.js";
import { requireAuth } from "../server.js";

export const deviceRoutes = express.Router();

/* =========================
   REGISTER DEVICE
========================= */
deviceRoutes.post("/register", requireAuth, async (req, res) => {
  try {
    const userId = req.qm.user.userId;

    const {
      device_id,
      label,
      device_type = "desktop",
      pub_jwk
    } = req.body || {};

    if (!device_id || !pub_jwk) {
      return res.status(400).json({ error: "device_id and pub_jwk required" });
    }

    const q = `
      insert into qm_devices
        (user_id, device_id, label, device_type, pub_jwk, status, created_at, last_seen_at, revoked)
      values
        ($1,$2,$3,$4,$5::jsonb,'active', now(), now(), false)
      on conflict (user_id, device_id) do update set
        label = excluded.label,
        device_type = excluded.device_type,
        pub_jwk = excluded.pub_jwk,
        status = 'active',
        last_seen_at = now(),
        revoked = false
      returning *
    `;

    const { rows } = await pool.query(q, [
      userId,
      String(device_id),
      String(label || ""),
      String(device_type || "desktop"),
      JSON.stringify(pub_jwk)
    ]);

    res.json({ ok: true, device: rows[0] });
  } catch (e) {
    console.error("device register failed:", e);
    res.status(500).json({ error: "device_register_failed", detail: e.message });
  }
});

/* =========================
   LIST DEVICES
========================= */
deviceRoutes.get("/list", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;

  const { rows } = await pool.query(
    `select user_id, device_id, label, device_type, pub_jwk, status, revoked, created_at
     from qm_devices
     where user_id = $1
     order by created_at desc`,
    [userId]
  );

  res.json({ ok: true, devices: rows });
});

/* =========================
   REVOKE DEVICE
========================= */
deviceRoutes.post("/revoke", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;
  const { device_id } = req.body;

  await pool.query(
    `update qm_devices
     set revoked = true, status = 'revoked'
     where user_id = $1 and device_id = $2`,
    [userId, device_id]
  );

  res.json({ ok: true });
});
