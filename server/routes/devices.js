// server/routes/devices.js
import express from "express";
import crypto from "crypto";
import { pool } from "../db.js";

export const deviceRoutes = express.Router();

/**
 * Uses your existing server auth middleware:
 * server.js sets req.qm = { tokenPayload, org, user } when authenticated. :contentReference[oaicite:2]{index=2}
 */
function requireAuth(req, res, next) {
  if (!req.qm?.user?.userId) return res.status(401).json({ error: "Unauthorized" });
  next();
}

function now() {
  return new Date().toISOString();
}

deviceRoutes.post("/register", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;
  const { device_id, label, pub_jwk } = req.body || {};

  if (!device_id || !pub_jwk) return res.status(400).json({ error: "missing_fields" });
  if (!String(device_id).startsWith("d_")) return res.status(400).json({ error: "bad_device_id" });

  const q = `
    insert into qm_devices (user_id, device_id, label, pub_jwk, created_at, last_seen_at, revoked)
    values ($1,$2,$3,$4::jsonb, now(), now(), false)
    on conflict (user_id, device_id)
    do update set label=excluded.label, pub_jwk=excluded.pub_jwk, last_seen_at=now(), revoked=false
    returning user_id, device_id, label, last_seen_at, revoked
  `;
  const vals = [userId, device_id, String(label || ""), JSON.stringify(pub_jwk)];
  const { rows } = await pool.query(q, vals);

  res.json({ ok: true, device: rows[0], at: now() });
});

deviceRoutes.get("/list", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;
  const { rows } = await pool.query(
    `select device_id, label, created_at, last_seen_at, revoked
     from qm_devices where user_id=$1 order by created_at desc`,
    [userId]
  );
  res.json({ ok: true, devices: rows });
});

deviceRoutes.post("/revoke", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;
  const { device_id } = req.body || {};
  if (!device_id) return res.status(400).json({ error: "missing_device_id" });

  await pool.query(
    `update qm_devices set revoked=true, last_seen_at=now()
     where user_id=$1 and device_id=$2`,
    [userId, device_id]
  );
  res.json({ ok: true });
});
