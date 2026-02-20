// server/mailer.js
import nodemailer from "nodemailer";

const SMTP_HOST = process.env.QM_SMTP_HOST || "";
const SMTP_PORT = parseInt(process.env.QM_SMTP_PORT || "587", 10);
const SMTP_USER = process.env.QM_SMTP_USER || "";
const SMTP_PASS = process.env.QM_SMTP_PASS || "";

const FROM_EMAIL = process.env.QM_FROM_EMAIL || SMTP_USER;
const FROM_NAME = process.env.QM_FROM_NAME || "QuantumMail";

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    throw new Error("Mailer not configured. Set QM_SMTP_HOST/QM_SMTP_USER/QM_SMTP_PASS");
  }

  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465, // true for 465, false for 587
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });

  return transporter;
}

export async function sendMail({ to, subject, html, text }) {
  const t = getTransporter();
  return t.sendMail({
    from: `${FROM_NAME} <${FROM_EMAIL}>`,
    to,
    subject,
    text: text || "",
    html: html || "",
  });
}
