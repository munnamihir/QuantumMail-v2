// server/mailer.js
import nodemailer from "nodemailer";

const SMTP_HOST = process.env.QM_SMTP_HOST || "";
const SMTP_PORT = parseInt(process.env.QM_SMTP_PORT || "587", 10);
const SMTP_USER = process.env.QM_SMTP_USER || "";
const SMTP_PASS = process.env.QM_SMTP_PASS || "";

const FROM_EMAIL = process.env.QM_FROM_EMAIL || SMTP_USER;
const FROM_NAME = process.env.QM_FROM_NAME || "QuantumMail";

// Optional knobs (help with picky providers)
const SMTP_SECURE = (process.env.QM_SMTP_SECURE || "").toLowerCase() === "true"; // force secure if needed
const SMTP_REQUIRE_TLS = (process.env.QM_SMTP_REQUIRE_TLS || "").toLowerCase() === "true"; // STARTTLS required
const SMTP_TLS_REJECT_UNAUTH = (process.env.QM_SMTP_TLS_REJECT_UNAUTH || "true").toLowerCase() === "true"; // keep true in prod
const SMTP_TLS_SERVERNAME = process.env.QM_SMTP_TLS_SERVERNAME || ""; // sometimes needed (SNI), usually same as host

let transporter = null;
let verifiedOnce = false;

function getTransporter() {
  if (transporter) return transporter;

  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    throw new Error("Mailer not configured. Set QM_SMTP_HOST/QM_SMTP_USER/QM_SMTP_PASS");
  }

  const secure = SMTP_SECURE ? true : (SMTP_PORT === 465);

  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure, // 465 => true, 587 => false (STARTTLS)
    auth: { user: SMTP_USER, pass: SMTP_PASS },

    // Fail fast instead of hanging forever
    connectionTimeout: 12_000,
    greetingTimeout: 12_000,
    socketTimeout: 20_000,

    // STARTTLS / TLS tweaks
    requireTLS: SMTP_REQUIRE_TLS,
    tls: {
      rejectUnauthorized: SMTP_TLS_REJECT_UNAUTH,
      servername: SMTP_TLS_SERVERNAME || SMTP_HOST,
    },
  });

  return transporter;
}

async function ensureVerified() {
  if (verifiedOnce) return;
  const t = getTransporter();

  // Log safe config (no secrets)
  console.log("MAIL CONFIG", {
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: (process.env.QM_SMTP_SECURE || "") || (SMTP_PORT === 465),
    requireTLS: SMTP_REQUIRE_TLS,
    fromEmail: FROM_EMAIL ? "set" : "missing",
    fromName: FROM_NAME,
    user: SMTP_USER ? "set" : "missing",
  });

  try {
    await t.verify();
    verifiedOnce = true;
    console.log("MAIL verify OK");
  } catch (e) {
    console.error("MAIL verify FAILED:", e?.message || e);
    throw e;
  }
}

export async function sendMail({ to, subject, html, text }) {
  await ensureVerified();
  const t = getTransporter();

  return t.sendMail({
    from: `${FROM_NAME} <${FROM_EMAIL}>`,
    to,
    subject,
    text: text || "",
    html: html || "",
  });
}
