// server/routes/recoveryQuorum.js
import express from "express";
import crypto from "crypto";
import { pool } from "../db.js";

export const recoveryQuorumRoutes = express.Router();

function requireAuth(req, res, next) {
  if (!req.qm?.user?.userId) return res.status(401).json({ error: "Unauthorized" });
  next();
}

function b64(buf) {
  return Buffer.from(buf).toString("base64");
}

function fromB64(s) {
  return Buffer.from(String(s || ""), "base64");
}

function isRecent(ts, minutes) {
  const t = Date.parse(ts);
  if (Number.isNaN(t)) return false;
  return Date.now() - t <= minutes * 60 * 1000;
}

async function importEd25519PublicJwk(pub_jwk) {
  // Node 18+ supports webcrypto
  const { webcrypto } = await import("crypto");
  return webcrypto.subtle.importKey(
    "jwk",
    pub_jwk,
    { name: "Ed25519" },
    true,
    ["verify"]
  );
}

async function verifyEd25519(pubKey, msgBytes, sigBytes) {
  const { webcrypto } = await import("crypto");
  return webcrypto.subtle.verify({ name: "Ed25519" }, pubKey, sigBytes, msgBytes);
}

/**
 * POST /api/recovery/quorum/start
 * Body: { token_id, token_verifier_hash, requester_device_id }
 * Returns: { request_id, nonce_b64 }
 */
recoveryQuorumRoutes.post("/quorum/start", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;
  const { token_id, token_verifier_hash, requester_device_id } = req.body || {};
  if (!token_id || !token_verifier_hash || !requester_device_id) {
    return res.status(400).json({ error: "missing_fields" });
  }

  const vault = await pool.query(
    `select user_id, token_id, token_verifier_hash, enc_wk_b64, iv_b64, wk_version, updated_at
     from qm_recovery_vault where user_id=$1`,
    [userId]
  );

  if (!vault.rows.length) return res.status(404).json({ error: "vault_not_found" });

  const row = vault.rows[0];
  if (row.token_id !== token_id) return res.status(403).json({ error: "token_id_mismatch" });
  if (row.token_verifier_hash !== token_verifier_hash) return res.status(403).json({ error: "bad_token" });

  // Require there exists at least 1 non-revoked trusted device OTHER than requester
  const devs = await pool.query(
    `select device_id from qm_devices
     where user_id=$1 and revoked=false and device_id <> $2`,
    [userId, requester_device_id]
  );
  if (devs.rows.length < 1) {
    return res.status(409).json({ error: "no_other_trusted_device" });
  }

  const request_id = "rq_" + crypto.randomBytes(12).toString("hex");
  const nonce = crypto.randomBytes(32);
  const nonce_b64 = b64(nonce);

  await pool.query(
    `insert into qm_recovery_requests (request_id, user_id, token_id, requester_device_id, nonce_b64, status, created_at)
     values ($1,$2,$3,$4,$5,'PENDING', now())`,
    [request_id, userId, token_id, requester_device_id, nonce_b64]
  );

  res.json({ ok: true, request_id, nonce_b64 });
});

/**
 * GET /api/recovery/quorum/pending
 * Returns PENDING requests for this user (so other devices can approve)
 */
recoveryQuorumRoutes.get("/quorum/pending", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;
  const { rows } = await pool.query(
    `select request_id, requester_device_id, nonce_b64, status, created_at
     from qm_recovery_requests
     where user_id=$1 and status='PENDING'
     order by created_at desc`,
    [userId]
  );
  res.json({ ok: true, requests: rows });
});

/**
 * POST /api/recovery/quorum/approve
 * Body: { request_id, device_id, sig_b64 }
 * Server verifies sig over: "qm-recover-v1|" + request_id + "|" + nonce_b64
 */
recoveryQuorumRoutes.post("/quorum/approve", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;
  const { request_id, device_id, sig_b64 } = req.body || {};
  if (!request_id || !device_id || !sig_b64) return res.status(400).json({ error: "missing_fields" });

  const rq = await pool.query(
    `select request_id, user_id, nonce_b64, status, created_at
     from qm_recovery_requests where request_id=$1 and user_id=$2`,
    [request_id, userId]
  );
  if (!rq.rows.length) return res.status(404).json({ error: "request_not_found" });

  const reqRow = rq.rows[0];
  if (reqRow.status !== "PENDING") return res.status(409).json({ error: "not_pending" });
  if (!isRecent(reqRow.created_at, 15)) {
    await pool.query(`update qm_recovery_requests set status='EXPIRED' where request_id=$1`, [request_id]);
    return res.status(410).json({ error: "expired" });
  }

  // load device pubkey
  const dev = await pool.query(
    `select pub_jwk, revoked from qm_devices where user_id=$1 and device_id=$2`,
    [userId, device_id]
  );
  if (!dev.rows.length) return res.status(404).json({ error: "device_not_found" });
  if (dev.rows[0].revoked) return res.status(403).json({ error: "device_revoked" });

  const msg = `qm-recover-v1|${request_id}|${reqRow.nonce_b64}`;
  const msgBytes = new TextEncoder().encode(msg);
  const sigBytes = fromB64(sig_b64);

  const pubKey = await importEd25519PublicJwk(dev.rows[0].pub_jwk);
  const ok = await verifyEd25519(pubKey, msgBytes, sigBytes);
  if (!ok) return res.status(403).json({ error: "bad_signature" });

  await pool.query(
    `insert into qm_recovery_approvals (request_id, user_id, device_id, sig_b64, approved_at)
     values ($1,$2,$3,$4, now())
     on conflict (request_id, device_id) do nothing`,
    [request_id, userId, device_id, sig_b64]
  );

  // 1-device quorum: approve immediately
  await pool.query(
    `update qm_recovery_requests set status='APPROVED', approved_at=now()
     where request_id=$1 and user_id=$2`,
    [request_id, userId]
  );

  res.json({ ok: true });
});

/**
 * POST /api/recovery/quorum/fetch
 * Body: { request_id, token_id, token_verifier_hash }
 * Returns vault blob if request APPROVED and token proof matches.
 */
recoveryQuorumRoutes.post("/quorum/fetch", requireAuth, async (req, res) => {
  const userId = req.qm.user.userId;
  const { request_id, token_id, token_verifier_hash } = req.body || {};
  if (!request_id || !token_id || !token_verifier_hash) return res.status(400).json({ error: "missing_fields" });

  const rq = await pool.query(
    `select request_id, user_id, status, token_id, created_at
     from qm_recovery_requests where request_id=$1 and user_id=$2`,
    [request_id, userId]
  );
  if (!rq.rows.length) return res.status(404).json({ error: "request_not_found" });
  const reqRow = rq.rows[0];
  if (reqRow.status !== "APPROVED") return res.status(403).json({ error: "not_approved" });
  if (!isRecent(reqRow.created_at, 15)) return res.status(410).json({ error: "expired" });

  const vault = await pool.query(
    `select user_id, token_id, token_verifier_hash, enc_wk_b64, iv_b64, wk_version, updated_at
     from qm_recovery_vault where user_id=$1`,
    [userId]
  );
  if (!vault.rows.length) return res.status(404).json({ error: "vault_not_found" });

  const v = vault.rows[0];
  if (v.token_id !== token_id) return res.status(403).json({ error: "token_id_mismatch" });
  if (v.token_verifier_hash !== token_verifier_hash) return res.status(403).json({ error: "bad_token" });

  res.json({
    ok: true,
    vault: {
      token_id: v.token_id,
      enc_wk_b64: v.enc_wk_b64,
      iv_b64: v.iv_b64,
      wk_version: v.wk_version
    }
  });
});
