/**
 * TEST-ONLY OTP retrieval — configuration and guard rails.
 *
 * WHY THIS EXISTS
 * SMS delivery is simulated (see server/lib/sms.js), so a simulated code
 * never actually reaches a phone. An evaluator still has to be able to
 * complete the mobile-verification step on a deployed instance, where the
 * server console is not visible. The assignment calls for a clearly
 * separated test-only retrieval mechanism, and this is it.
 *
 * WHAT IT IS NOT
 * It is not part of the normal API surface. POST /api/send-sms-otp never
 * returns the code. Nothing in the frontend calls this. It lives behind
 * its own route file, its own env flag and its own bearer token.
 *
 * THE TRADE-OFF, STATED PLAINLY
 * Codes are stored only as a SHA-256 hash, which cannot be reversed. So
 * to hand a code back, the plaintext has to be kept somewhere. When — and
 * only when — this API is enabled, the code is also written to
 * otp_challenges.test_otp. With the flag off (the default) that column
 * stays NULL and no plaintext OTP exists anywhere in the system.
 *
 * FOUR CONDITIONS, ALL REQUIRED
 *   1. ENABLE_TEST_OTP_API=true            (defaults to false)
 *   2. TEST_OTP_TOKEN set, >= 16 chars     (no token, no endpoint)
 *   3. SMS_MODE=mock                       (refuses with a real provider)
 *   4. every request carries that token    (constant-time compared)
 */

const crypto = require("crypto");

const FLAG = String(process.env.ENABLE_TEST_OTP_API || "false").toLowerCase() === "true";
const TOKEN = process.env.TEST_OTP_TOKEN || "";
const SMS_MODE = (process.env.SMS_MODE || "mock").toLowerCase();

/** Reasons the API is refused, for an honest startup banner. */
function disabledReason() {
  if (!FLAG) return null; // not requested at all — silence is correct
  if (SMS_MODE !== "mock") {
    return `refused: SMS_MODE=${SMS_MODE}. The test OTP API is only allowed with simulated SMS.`;
  }
  if (!TOKEN) return "refused: TEST_OTP_TOKEN is not set.";
  if (TOKEN.length < 16) return "refused: TEST_OTP_TOKEN must be at least 16 characters.";
  return null;
}

const REASON = disabledReason();
const ENABLED = FLAG && REASON === null;

/** True when the plaintext code should be persisted for later retrieval. */
function shouldStoreTestOtp() {
  return ENABLED;
}

/** Constant-time token check — avoids leaking the token via response timing. */
function tokenMatches(supplied) {
  const a = Buffer.from(String(supplied || ""), "utf8");
  const b = Buffer.from(TOKEN, "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function describeTestConfig() {
  if (!FLAG) return "disabled (normal)";
  if (REASON) return REASON;
  return "ENABLED — GET /api/test/otp is live. Never leave this on for real accounts.";
}

module.exports = {
  ENABLED,
  shouldStoreTestOtp,
  tokenMatches,
  describeTestConfig,
};
