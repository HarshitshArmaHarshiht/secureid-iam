/**
 * SMS delivery.
 *
 * SMS_MODE picks the transport:
 *   mock     — no message leaves the server. The OTP is still generated
 *              with a CSPRNG, still hashed before storage, still expires,
 *              still attempt-limited and single-use. Only the *transport*
 *              is stubbed, so the security properties and the UI flow are
 *              identical to production.
 *   http     — a generic HTTP provider configured entirely through env
 *              vars, so a real gateway can be dropped in without a code
 *              change (see SMS_HTTP_* below).
 *
 * Why mock is the default: every SMS gateway that can actually deliver to
 * an Indian (+91) number requires a paid, KYC-verified, DLT-registered
 * sender. Twilio trial credit does not cover it and free tiers do not
 * exist for this route. Real SMS delivery costs money — there is no way
 * around that, so the architecture is built for it while the default
 * configuration stays free.
 */

const MODE = (process.env.SMS_MODE || "mock").toLowerCase();

/**
 * Retrieving a simulated code:
 *   - locally, read it from the server console (printed below), or
 *   - use the TEST-ONLY API in server/routes/testing.js, which is behind
 *     its own env flag and bearer token.
 *
 * The OTP is never included in a normal API response.
 */

async function sendOtpSms(to, otp, ttlSeconds) {
  const body = `${otp} is your SecureID verification code. It expires in ${Math.round(
    ttlSeconds / 60
  )} minutes. Do not share it with anyone.`;

  if (MODE === "mock") {
    console.log(
      `\n[SMS:mock] to=${to}  OTP=${otp}  (expires in ${ttlSeconds}s)\n` +
        `  No SMS was sent. Real delivery needs a paid, DLT-registered gateway.\n`
    );
    return { delivered: false, mode: "mock" };
  }

  if (MODE === "http") {
    const url = process.env.SMS_HTTP_URL;
    if (!url) throw new Error("SMS_MODE=http but SMS_HTTP_URL is not set.");

    // Provider-agnostic: the operator supplies the URL, method, headers
    // and a body template. {{to}} / {{message}} are substituted.
    const template = process.env.SMS_HTTP_BODY || '{"to":"{{to}}","message":"{{message}}"}';
    const payload = template
      .replace(/\{\{to\}\}/g, to)
      .replace(/\{\{message\}\}/g, body.replace(/"/g, '\\"'));

    const headers = { "Content-Type": "application/json" };
    if (process.env.SMS_HTTP_AUTH_HEADER) {
      headers[process.env.SMS_HTTP_AUTH_HEADER] = process.env.SMS_HTTP_AUTH_VALUE || "";
    }

    const res = await fetch(url, {
      method: process.env.SMS_HTTP_METHOD || "POST",
      headers,
      body: payload,
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new Error(`SMS provider rejected the message (${res.status}): ${detail.slice(0, 200)}`);
    }
    return { delivered: true, mode: "http" };
  }

  throw new Error(`Unknown SMS_MODE "${MODE}". Use "mock" or "http".`);
}

function describeSmsConfig() {
  if (MODE === "mock") {
    return "mock (no SMS sent; codes printed to this console)";
  }
  return `http via ${process.env.SMS_HTTP_URL || "MISSING SMS_HTTP_URL"}`;
}

module.exports = { sendOtpSms, describeSmsConfig, SMS_MODE: MODE };
