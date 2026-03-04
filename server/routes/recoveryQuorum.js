// server/routes/recoveryQuorum.js
import express from "express";
import crypto from "crypto";
import { pool } from "../db.js";

export const recoveryQuorumRoutes = express.Router();

/**
 * NOTE:
 * In server.js you already mount this router behind requireAuth:
 *   app.use("/api/recovery", requireAuth, recoveryQuorumRoutes);
 * So this router assumes req.qm.user exists.
 */

function ensureAuthed(req, res) {
  if (!req.qm?.user?.userId) {
    res.status(401).json({ error: "Unauthorized" });
    return false;
  }
  return true;
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
  // Node supports Ed25519 in WebCrypto.
  // Use the built-in webcrypto on node:crypto.
  return crypto.webcrypto.subtle.importKey("jwk", pub_jwk, { name: "Ed25519" }, true, ["verify"]);
}

async function verifyEd25519(pubKey, msgBytes, sigBytes) {
  return crypto.webcrypto.subtle.verify({ name: "Ed25519" }, pubKey, sigBytes, msgBytes);
}

/**
 * POST /api/recovery/quorum/start
 * Body: { token_id, token_verifier_hash, requester_device_id }
 * Returns: { request_id, nonce_b64 }
 */
recoveryQuorumRoutes.post("/quorum/start", async (req, res) => {
  if (!ensureAuthed(req, res)) return;

  const userId = req.qm.user.userId;
  const { token_id, token_verifier_hash, requester_device_id } = req.body || {};

  if (!token_id || !token_verifier_hash || !requester_device_id) {
    return res.status(400).json({ error: "missing_fields" });
  }

  // Confirm vault exists + token proof matches (server stores token_verifier_hash)
  const vaultQ = await pool.query(
    `select user_id, token_id, token_verifier_hash
       from qm_recovery_vault
      where user_id=$1
      limit 1`,
    [userId]
  );
  if (!vaultQ.rows.length) return res.status(404).json({ error: "vault_not_found" });

  const v = vaultQ.rows[0];
  if (v.token_id !== token_id) return res.status(403).json({ error: "token_id_mismatch" });
  if (v.token_verifier_hash !== token_verifier_hash) return res.status(403).json({ error: "bad_token" });

  // Require there exists at least 1 trusted device other than the requester
  const devs = await pool.query(
    `select device_id
       from qm_devices
      where user_id=$1
        and revoked=false
        and device_id <> $2
      limit 1`,
    [userId, requester_device_id]
  );
  if (devs.rows.length < 1) {
    return res.status(409).json({ error: "no_other_trusted_device" });
  }

  const request_id = "rq_" + crypto.randomBytes(12).toString("hex");
  const nonce = crypto.randomBytes(32);
  const nonce_b64 = b64(nonce);

  await pool.query(
    `insert into qm_recovery_requests
      (request_id, user_id, token_id, requester_device_id, nonce_b64, status, created_at)
     values
      ($1,$2,$3,$4,$5,'PENDING', now())`,
    [request_id, userId, token_id, requester_device_id, nonce_b64]
  );

  return res.json({ ok: true, request_id, nonce_b64 });
});

/**
 * GET /api/recovery/quorum/pending
 * Returns PENDING requests for this user (so trusted devices can approve)
 */
recoveryQuorumRoutes.get("/quorum/pending", async (req, res) => {
  if (!ensureAuthed(req, res)) return;

  const userId = req.qm.user.userId;

  const { rows } = await pool.query(
    `select request_id, requester_device_id, nonce_b64, status, created_at
       from qm_recovery_requests
      where user_id=$1
        and status='PENDING'
      order by created_at desc
      limit 50`,
    [userId]
  );

  return res.json({ ok: true, requests: rows });
});

/**
 * POST /api/recovery/quorum/approve
 * Body: { request_id, device_id, sig_b64 }
 * Server verifies sig over: "qm-recover-v1|<request_id>|<nonce_b64>"
 */
recoveryQuorumRoutes.post("/quorum/approve", async (req, res) => {
  if (!ensureAuthed(req, res)) return;

  const userId = req.qm.user.userId;
  const { request_id, device_id, sig_b64 } = req.body || {};

  if (!request_id || !device_id || !sig_b64) {
    return res.status(400).json({ error: "missing_fields" });
  }

  // Load request ONCE (your old file re-declared rq and re-queried incorrectly)
  const rqQ = await pool.query(
    `select request_id, user_id, requester_device_id, nonce_b64, status, created_at
       from qm_recovery_requests
      where request_id=$1 and user_id=$2
      limit 1`,
    [request_id, userId]
  );
  if (!rqQ.rows.length) return res.status(404).json({ error: "request_not_found" });

  const reqRow = rqQ.rows[0];

  if (reqRow.status !== "PENDING") return res.status(409).json({ error: "not_pending" });

  if (!isRecent(reqRow.created_at, 15)) {
    await pool.query(`update qm_recovery_requests set status='EXPIRED' where request_id=$1 and user_id=$2`, [
      request_id,
      userId
    ]);
    return res.status(410).json({ error: "expired" });
  }

  // Prevent self-approval
  if (device_id === reqRow.requester_device_id) {
    return res.status(403).json({ error: "self_approval_not_allowed" });
  }

  // Load device public key (must be trusted + not revoked)
  const devQ = await pool.query(
    `select pub_jwk, revoked
       from qm_devices
      where user_id=$1 and device_id=$2
      limit 1`,
    [userId, device_id]
  );
  if (!devQ.rows.length) return res.status(404).json({ error: "device_not_found" });
  if (devQ.rows[0].revoked) return res.status(403).json({ error: "device_revoked" });

  // Verify signature
  const msg = `qm-recover-v1|${request_id}|${reqRow.nonce_b64}`;
  const msgBytes = new TextEncoder().encode(msg);
  const sigBytes = fromB64(sig_b64);

  let pubKey;
  try {
    pubKey = await importEd25519PublicJwk(devQ.rows[0].pub_jwk);
  } catch (e) {
    return res.status(400).json({ error: "bad_device_pubkey", detail: String(e?.message || e) });
  }

  const ok = await verifyEd25519(pubKey, msgBytes, sigBytes);
  if (!ok) return res.status(403).json({ error: "bad_signature" });

  // Record approval (idempotent)
  await pool.query(
    `insert into qm_recovery_approvals (request_id, user_id, device_id, sig_b64, approved_at)
     values ($1,$2,$3,$4, now())
     on conflict (request_id, device_id) do nothing`,
    [request_id, userId, device_id, sig_b64]
  );

  // 1-device quorum => approve request immediately
  await pool.query(
    `update qm_recovery_requests
        set status='APPROVED',
            approved_at=now()
      where request_id=$1 and user_id=$2`,
    [request_id, userId]
  );

  return res.json({ ok: true });
});

/**
 * POST /api/recovery/quorum/fetch
 * Body: { request_id, token_id, token_verifier_hash }
 * Returns: vault blob if request APPROVED and token proof matches.
 */
recoveryQuorumRoutes.post("/quorum/fetch", async (req, res) => {
  if (!ensureAuthed(req, res)) return;

  const userId = req.qm.user.userId;
  const { request_id, token_id, token_verifier_hash } = req.body || {};

  if (!request_id || !token_id || !token_verifier_hash) {
    return res.status(400).json({ error: "missing_fields" });
  }

  const rqQ = await pool.query(
    `select request_id, user_id, status, token_id, created_at
       from qm_recovery_requests
      where request_id=$1 and user_id=$2
      limit 1`,
    [request_id, userId]
  );
  if (!rqQ.rows.length) return res.status(404).json({ error: "request_not_found" });

  const reqRow = rqQ.rows[0];
  if (reqRow.status !== "APPROVED") return res.status(403).json({ error: "not_approved" });
  if (!isRecent(reqRow.created_at, 15)) return res.status(410).json({ error: "expired" });

  const vaultQ = await pool.query(
    `select token_id, token_verifier_hash, enc_wk_b64, iv_b64, wk_version
       from qm_recovery_vault
      where user_id=$1
      limit 1`,
    [userId]
  );
  if (!vaultQ.rows.length) return res.status(404).json({ error: "vault_not_found" });

  const v = vaultQ.rows[0];
  if (v.token_id !== token_id) return res.status(403).json({ error: "token_id_mismatch" });
  if (v.token_verifier_hash !== token_verifier_hash) return res.status(403).json({ error: "bad_token" });

  return res.json({
    ok: true,
    vault: {
      token_id: v.token_id,
      enc_wk_b64: v.enc_wk_b64,
      iv_b64: v.iv_b64,
      wk_version: v.wk_version
    }
  });
});
