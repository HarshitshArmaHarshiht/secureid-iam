const crypto = require("crypto");

const OTP_LENGTH = 6;
const OTP_TTL_MS = 2 * 60 * 1000 + 45 * 1000; // 2:45, matches the mock UI
const MAX_ATTEMPTS = 3;

/**
 * Generate a numeric OTP as a string, e.g. "482913".
 *
 * crypto.randomInt is a CSPRNG and is rejection-sampled internally, so
 * every digit is uniformly distributed. Math.random() would be
 * predictable from a handful of observed codes and must never be used here.
 */
function generateOtp() {
  let otp = "";
  for (let i = 0; i < OTP_LENGTH; i++) {
    otp += crypto.randomInt(0, 10).toString();
  }
  return otp;
}

/**
 * One-way hash of the OTP so the raw code is never stored.
 *
 * Plain SHA-256 (not bcrypt) is deliberate: the input space is only 10^6
 * and the code dies after 2:45 with a 3-attempt cap, so a slow KDF buys
 * nothing here while costing latency on every verify.
 */
function hashOtp(otp) {
  return crypto.createHash("sha256").update(String(otp)).digest("hex");
}

/** Constant-time comparison — never leak which prefix matched via timing. */
function verifyOtpHash(otp, hash) {
  const candidate = hashOtp(otp);
  const a = Buffer.from(candidate, "utf8");
  const b = Buffer.from(String(hash || ""), "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

module.exports = {
  OTP_LENGTH,
  OTP_TTL_MS,
  MAX_ATTEMPTS,
  generateOtp,
  hashOtp,
  verifyOtpHash,
};
