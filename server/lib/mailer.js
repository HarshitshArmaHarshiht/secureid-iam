/**
 * Email delivery.
 *
 * EMAIL_MODE picks the transport:
 *   smtp   — Nodemailer over SMTP (Gmail app password, Brevo, Mailtrap…).
 *            The simplest genuinely-free option that can reach ANY inbox.
 *   resend — Resend's HTTP API. Free tier is 3,000/month, but without a
 *            verified domain it can only send to your own account email.
 *   mock   — prints to the server console. Used by tests and offline dev.
 *
 * Credentials come from environment variables only — never hard-coded,
 * never committed. See .env.example.
 */

const MODE = (process.env.EMAIL_MODE || "mock").toLowerCase();
const FROM = process.env.EMAIL_FROM || "SecureID <onboarding@resend.dev>";

let transporterPromise = null;

function getTransporter() {
  if (!transporterPromise) {
    const nodemailer = require("nodemailer");
    transporterPromise = Promise.resolve(
      nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: Number(process.env.EMAIL_PORT || 587),
        // 465 = implicit TLS; 587 = STARTTLS upgrade.
        secure: Number(process.env.EMAIL_PORT || 587) === 465,
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASSWORD },
      })
    );
  }
  return transporterPromise;
}

function otpEmail(otp, ttlSeconds) {
  const minutes = Math.floor(ttlSeconds / 60);
  const seconds = ttlSeconds % 60;
  const validFor = `${minutes}:${String(seconds).padStart(2, "0")}`;

  const text =
    `Your SecureID verification code is ${otp}\n\n` +
    `It is valid for ${validFor} minutes and can be used once.\n` +
    `If you did not request this, you can ignore this email.`;

  const html = `
<div style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;color:#0f172a">
  <h1 style="margin:0 0 4px;font-size:20px;color:#1e3a8a">SecureID</h1>
  <p style="margin:0 0 28px;color:#64748b;font-size:14px">Secure access to your account</p>
  <p style="margin:0 0 16px;font-size:15px">Your verification code is:</p>
  <div style="font-size:34px;font-weight:700;letter-spacing:10px;color:#1e3a8a;background:#eff6ff;border-radius:10px;padding:18px;text-align:center">${otp}</div>
  <p style="margin:24px 0 0;color:#64748b;font-size:13px">
    Valid for ${validFor} minutes. It can be used once.<br />
    If you did not request this, you can safely ignore this email.
  </p>
</div>`.trim();

  return { subject: `${otp} is your SecureID verification code`, text, html };
}

/**
 * Send an OTP by email. Resolves to a small result object; throws only on
 * a genuine transport failure so the caller can surface a generic error.
 */
async function sendOtpEmail(to, otp, ttlSeconds) {
  const { subject, text, html } = otpEmail(otp, ttlSeconds);

  if (MODE === "mock") {
    console.log(
      `\n[EMAIL:mock] to=${to}  OTP=${otp}  (expires in ${ttlSeconds}s)\n` +
        `  Set EMAIL_MODE=smtp in .env to deliver this for real.\n`
    );
    return { delivered: false, mode: "mock" };
  }

  if (MODE === "resend") {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ from: FROM, to: [to], subject, text, html }),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new Error(`Resend rejected the message (${res.status}): ${detail.slice(0, 200)}`);
    }
    return { delivered: true, mode: "resend" };
  }

  // Default: SMTP via Nodemailer.
  const transporter = await getTransporter();
  await transporter.sendMail({ from: FROM, to, subject, text, html });
  return { delivered: true, mode: "smtp" };
}

/** Startup sanity check so misconfiguration surfaces early, not mid-signup. */
function describeEmailConfig() {
  if (MODE === "mock") return "mock (codes print to the server console)";
  if (MODE === "resend") {
    return process.env.RESEND_API_KEY ? `resend (from ${FROM})` : "resend — MISSING RESEND_API_KEY";
  }
  const missing = ["EMAIL_HOST", "EMAIL_USER", "EMAIL_PASSWORD"].filter((k) => !process.env[k]);
  return missing.length
    ? `smtp — MISSING ${missing.join(", ")}`
    : `smtp via ${process.env.EMAIL_HOST}:${process.env.EMAIL_PORT || 587} (from ${FROM})`;
}

module.exports = { sendOtpEmail, describeEmailConfig, EMAIL_MODE: MODE };
