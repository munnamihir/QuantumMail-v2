// server/emailer.js
import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY);
const FROM = process.env.MAIL_FROM || "QuantumMail <no-reply@quantummail-v2.onrender.com>";

export async function sendEmail({ to, subject, html, text }) {
  return resend.emails.send({ from: FROM, to, subject, html, text });
}
