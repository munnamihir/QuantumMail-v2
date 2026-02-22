// server/routes/recovery.js
import express from "express";
import crypto from "crypto";

export function recoveryRoutes({ getOrg, saveOrg, sendMail, hashPassword }) {
  if (!getOrg || !saveOrg) throw new Error("recoveryRoutes requires getOrg/saveOrg");
  if (!sendMail) throw new Error("recoveryRoutes requires sendMail");
  if (!hashPassword) throw new Error("recoveryRoutes requires hashPassword");

  const router = express.Router();

  function normEmail(s) {
    return String(s || "").trim().toLowerCase();
  }

  function sha256Hex(s) {
    return crypto.createHash("sha256").update(String(s)).digest("hex");
  }

  function randomToken(lenBytes = 24) {
    return crypto.randomBytes(lenBytes).toString("hex");
  }

  function random6() {
    return String(Math.floor(100000 + Math.random() * 900000));
  }

  function nowIso() {
    return new Date().toISOString();
  }

  function ensureResetShape(user) {
    if (!user.reset) user.reset = {};
    user.reset.tokenHash ??= null;
    user.reset.tokenExpiresAt ??= null;
    user.reset.otpHash ??= null;
    user.reset.otpExpiresAt ??= null;
    user.reset.otpAttempts ??= 0;
    user.reset.verifiedAt ??= null;
    return user;
  }

  function findUserByEmail(org, email) {
    const e = normEmail(email);
    return (org.users || []).find(u => normEmail(u.email) === e) || null;
  }

  /* =========================================================
     POST /auth/forgot-username
     - Security: always returns generic message
     - Action: emails username if match exists
  ========================================================= */
  router.post("/auth/forgot-username", async (req, res) => {
    const generic = { ok: true, message: "If an account exists, you will receive an email shortly." };

    try {
      const orgId = String(req.body.orgId || "").trim();
      const email = normEmail(req.body.email);

      if (!orgId || !email) return res.json(generic);

      const org = await getOrg(orgId);
      const user = findUserByEmail(org, email);
      if (!user) return res.json(generic);

      await sendMail({
        to: email,
        subject: "QuantumMail — Your username",
        html: `
          <div style="font-family:system-ui,Segoe UI,Arial">
            <h2>Your QuantumMail username</h2>
            <p>Org: <b>${orgId}</b></p>
            <p>Username: <b>${String(user.username || "")}</b></p>
            <p style="color:#666">If you didn’t request this, ignore this email.</p>
          </div>
        `
      });

      org.audit = Array.isArray(org.audit) ? org.audit : [];
      org.audit.unshift({ at: nowIso(), action: "forgot_username", username: user.username, userId: user.userId, ip: req.ip });
      await saveOrg(orgId, org);

      return res.json(generic);
    } catch {
      return res.json(generic);
    }
  });

  /* =========================================================
     POST /auth/forgot-password
     - Security: always returns generic message
     - Action: creates token, emails reset link
  ========================================================= */
  router.post("/auth/forgot-password", async (req, res) => {
    const generic = { ok: true, message: "If an account exists, you’ll receive a reset link shortly." };

    try {
      const orgId = String(req.body.orgId || "").trim();
      const email = normEmail(req.body.email);

      if (!orgId || !email) return res.json(generic);

      const org = await getOrg(orgId);
      const user = findUserByEmail(org, email);
      if (!user) return res.json(generic);

      ensureResetShape(user);

      const resetToken = randomToken(24); // raw token (not stored)
      user.reset.tokenHash = sha256Hex(resetToken);
      user.reset.tokenExpiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 min
      user.reset.otpHash = null;
      user.reset.otpExpiresAt = null;
      user.reset.otpAttempts = 0;
      user.reset.verifiedAt = null;

      await saveOrg(orgId, org);

      const base = process.env.PUBLIC_BASE_URL || "http://localhost:5173";
      const link = `${base}/portal/reset.html?orgId=${encodeURIComponent(orgId)}&token=${encodeURIComponent(resetToken)}`;

      await sendMail({
        to: email,
        subject: "QuantumMail — Reset your password",
        html: `
          <div style="font-family:system-ui,Segoe UI,Arial">
            <h2>Reset your QuantumMail password</h2>
            <p>Org: <b>${orgId}</b></p>
            <p>Click the button below to continue:</p>
            <p>
              <a href="${link}" style="display:inline-block;padding:12px 14px;border-radius:10px;background:#2bd576;color:#07101f;text-decoration:none;font-weight:800">
                Open Reset Page
              </a>
            </p>
            <p style="color:#666">This link expires in 15 minutes.</p>
          </div>
        `
      });

      org.audit = Array.isArray(org.audit) ? org.audit : [];
      org.audit.unshift({ at: nowIso(), action: "forgot_password_link_sent", username: user.username, userId: user.userId, ip: req.ip });
      await saveOrg(orgId, org);

      return res.json(generic);
    } catch {
      return res.json(generic);
    }
  });

  /* =========================================================
     POST /auth/reset/send-code
     - Validates reset token
     - Emails OTP code (6 digits)
  ========================================================= */
  router.post("/auth/reset/send-code", async (req, res) => {
    try {
      const orgId = String(req.body.orgId || "").trim();
      const token = String(req.body.token || "").trim();
      if (!orgId || !token) return res.status(400).json({ error: "Missing orgId or token" });

      const org = await getOrg(orgId);
      const tokenHash = sha256Hex(token);

      const user = (org.users || []).find(u => u?.reset?.tokenHash === tokenHash);
      if (!user) return res.status(400).json({ error: "Invalid or expired reset link" });

      ensureResetShape(user);

      const exp = Date.parse(user.reset.tokenExpiresAt || "");
      if (!exp || Date.now() > exp) return res.status(400).json({ error: "Reset link expired" });

      const code = random6();
      user.reset.otpHash = sha256Hex(code);
      user.reset.otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 min
      user.reset.otpAttempts = 0;
      user.reset.verifiedAt = null;

      await saveOrg(orgId, org);

      const to = normEmail(user.email);
      if (!to) return res.status(400).json({ error: "Account has no email on file. Ask Admin to add email." });

      await sendMail({
        to,
        subject: "QuantumMail — Verification code",
        html: `
          <div style="font-family:system-ui,Segoe UI,Arial">
            <h2>Your verification code</h2>
            <p>Use this code to reset your password:</p>
            <div style="font-size:28px;font-weight:900;letter-spacing:6px">${code}</div>
            <p style="color:#666">Code expires in 10 minutes.</p>
          </div>
        `
      });

      org.audit = Array.isArray(org.audit) ? org.audit : [];
      org.audit.unshift({ at: nowIso(), action: "reset_code_sent", username: user.username, userId: user.userId, ip: req.ip });
      await saveOrg(orgId, org);

      return res.json({ ok: true });
    } catch (e) {
      return res.status(500).json({ error: e?.message || "Failed to send code" });
    }
  });

  /* =========================================================
     POST /auth/reset/confirm
     - Validates token + code
     - Sets new password hash
     - Invalidates reset session
  ========================================================= */
  router.post("/auth/reset/confirm", async (req, res) => {
    try {
      const orgId = String(req.body.orgId || "").trim();
      const token = String(req.body.token || "").trim();
      const code = String(req.body.code || "").trim();
      const newPassword = String(req.body.newPassword || "");

      if (!orgId || !token || !code || !newPassword) {
        return res.status(400).json({ error: "Missing required fields" });
      }
      if (newPassword.length < 12) return res.status(400).json({ error: "New password must be at least 12 characters" });

      const org = await getOrg(orgId);
      const tokenHash = sha256Hex(token);

      const user = (org.users || []).find(u => u?.reset?.tokenHash === tokenHash);
      if (!user) return res.status(400).json({ error: "Invalid reset session" });

      ensureResetShape(user);

      const tokenExp = Date.parse(user.reset.tokenExpiresAt || "");
      if (!tokenExp || Date.now() > tokenExp) return res.status(400).json({ error: "Reset link expired" });

      const otpExp = Date.parse(user.reset.otpExpiresAt || "");
      if (!otpExp || Date.now() > otpExp) return res.status(400).json({ error: "Verification code expired" });

      if ((user.reset.otpAttempts || 0) >= 6) {
        return res.status(400).json({ error: "Too many attempts. Restart reset." });
      }

      const okCode = sha256Hex(code) === user.reset.otpHash;
      if (!okCode) {
        user.reset.otpAttempts = (user.reset.otpAttempts || 0) + 1;
        await saveOrg(orgId, org);
        return res.status(400).json({ error: "Invalid code" });
      }

      // ✅ hash password using your real hashing function
      user.passwordHash = await hashPassword(newPassword);

      user.reset.verifiedAt = nowIso();
      user.reset.tokenHash = null;
      user.reset.tokenExpiresAt = null;
      user.reset.otpHash = null;
      user.reset.otpExpiresAt = null;
      user.reset.otpAttempts = 0;

      await saveOrg(orgId, org);

      org.audit = Array.isArray(org.audit) ? org.audit : [];
      org.audit.unshift({ at: nowIso(), action: "password_reset_success", username: user.username, userId: user.userId, ip: req.ip });
      await saveOrg(orgId, org);

      return res.json({ ok: true });
    } catch (e) {
      return res.status(500).json({ error: e?.message || "Reset failed" });
    }
  });

  return router;
}
