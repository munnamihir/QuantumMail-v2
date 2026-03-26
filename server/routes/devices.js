// server/routes/devices.js
import express from "express";
import { pool } from "../db.js";
import { requireAuth } from "../server.js";

export const deviceRoutes = express.Router();

/*export function requireAuth(req, res, next) {
  if (!req.qm?.user?.userId) return res.status(401).json({ error: "Unauthorized" });
  next();
}*/

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
        (user_id, device_id, label, device_type, pub_jwk, created_at, last_seen_at, revoked)
      values
        ($1,$2,$3,$4,$5::jsonb, now(), now(), false)
      on conflict (user_id, device_id) do update set
        label = excluded.label,
        device_type = excluded.device_type,
        pub_jwk = excluded.pub_jwk,
        last_seen_at = now(),
        revoked = false
      returning user_id, device_id, label, device_type, created_at, last_seen_at, revoked
    `;

    const vals = [
      userId,
      String(device_id),
      String(label || ""),
      String(device_type || "desktop"),
      JSON.stringify(pub_jwk)
    ];

    const { rows } = await pool.query(q, vals);
    res.json({ ok: true, device: rows[0] });
  } catch (e) {
    console.error("POST /api/devices/register failed:", e);
    res.status(500).json({ error: "device_register_failed", detail: String(e?.message || e) });
  }
});

deviceRoutes.get("/list", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;

  const { rows } = await pool.query(
    `select user_id, device_id, label, device_type, pub_jwk, created_at, last_seen_at, revoked
       from qm_devices
      where user_id = $1
      order by created_at desc`,
    [userId]
  );

  res.json({ ok: true, devices: rows });
});

deviceRoutes.post("/revoke", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;
  const { device_id } = req.body || {};

  if (!device_id) return res.status(400).json({ error: "device_id required" });

  await pool.query(
    `update qm_devices
        set revoked = true,
            last_seen_at = now()
      where user_id = $1 and device_id = $2`,
    [userId, String(device_id)]
  );

  res.json({
    ok: true,
    devices: rows.map(d => ({
      deviceId: d.device_id,
      label: d.label,
      deviceType: d.device_type,
      publicKeySpkiB64: d.pub_jwk?.publicKeySpkiB64,
      status: d.revoked ? "revoked" : "active"
    }))
  });
});
