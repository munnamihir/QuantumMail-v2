import express from "express";
import { pool } from "../db.js";
import { requireAuth } from "../server.js";

export const deviceRoutes = express.Router();

/* =========================
   REGISTER DEVICE (PENDING)
========================= */
deviceRoutes.post("/register", requireAuth, async (req, res) => {
  try {
    const userId = req.qm.user.userId;

    const {
      device_id,
      label = "Chrome Extension",
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
        ($1,$2,$3,$4,$5::jsonb,'pending', now(), now(), false)
      on conflict (user_id, device_id) do update set
        pub_jwk = excluded.pub_jwk,
        last_seen_at = now()
      returning *
    `;

    const { rows } = await pool.query(q, [
      userId,
      device_id,
      label,
      device_type,
      JSON.stringify(pub_jwk)
    ]);

    res.json({ ok: true, device: rows[0] });
  } catch (e) {
    console.error("REGISTER ERROR:", e);
    res.status(500).json({ error: "device_register_failed", detail: e.message });
  }
});

/* =========================
   TRUST DEVICE (UPDATE)
========================= */
deviceRoutes.post("/trust", requireAuth, async (req, res) => {
  try {
    const userId = req.qm.user.userId;
    const { device_id, label, device_type } = req.body;

    if (!device_id) {
      return res.status(400).json({ error: "device_id required" });
    }

    const { rows } = await pool.query(
      `update qm_devices
         set status = 'active',
             label = coalesce($3, label),
             device_type = coalesce($4, device_type),
             last_seen_at = now()
       where user_id = $1 and device_id = $2
       returning *`,
      [userId, device_id, label, device_type]
    );

    if (!rows.length) {
      return res.status(404).json({ error: "Device not found" });
    }

    res.json({ ok: true, device: rows[0] });
  } catch (e) {
    console.error("TRUST ERROR:", e);
    res.status(500).json({ error: "device_trust_failed", detail: e.message });
  }
});

/* =========================
   LIST DEVICES
========================= */
deviceRoutes.get("/list", requireAuth, async (req, res) => {
  try {
    const userId = req.qm.user.userId;

    const { rows } = await pool.query(
      `select user_id, device_id, label, device_type, pub_jwk, status, revoked, created_at
       from qm_devices
       where user_id = $1
       order by created_at desc`,
      [userId]
    );

    res.json({ ok: true, devices: rows });
  } catch (e) {
    console.error("LIST ERROR:", e);
    res.status(500).json({ error: "device_list_failed", detail: e.message });
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
      `update qm_devices
         set revoked = true
       where user_id = $1 and device_id = $2`,
      [userId, device_id]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error("REVOKE ERROR:", e);
    res.status(500).json({ error: "device_revoke_failed", detail: e.message });
  }
});
