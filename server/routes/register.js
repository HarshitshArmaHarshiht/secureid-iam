/**
 * Registration journey:
 *   POST /api/register            → create account, send email OTP
 *   POST /api/send-email-otp      → resend
 *   POST /api/verify-email-otp
 *   POST /api/send-sms-otp
 *   POST /api/verify-sms-otp
 *   POST /api/mfa/setup           → TOTP secret + QR, or an SMS/email code
 *   POST /api/mfa/verify          → completes registration
 *
 * IDENTITY RULE: only /api/register takes the user's details from the body.
 * Every later step reads the userId from the signed HttpOnly `reg_session`
 * cookie via requireRegistrationSession. A userId in the request body is
 * ignored entirely — that is what makes it impossible to verify your own
 * OTP while pointing at somebody else's account.
 */

const express = require("express");

const users = require("../lib/users");
const { validateRegistration } = require("../lib/validate");
const { createChallenge, verifyChallenge, challengeResponse, RESULT } = require("../lib/challenge");
const { MAX_ATTEMPTS } = require("../lib/otp");
const mfa = require("../lib/mfa");
const { limiter, clientIp } = require("../lib/ratelimit");
const {
  issueRegistrationCookie,
  clearRegistrationCookie,
  requireRegistrationSession,
} = require("../lib/auth");

const router = express.Router();

/* ------------------------------------------------------------------ */
/* Rate limits                                                         */
/*                                                                     */
/* Two layers: per-IP (stops one machine mass-registering) and         */
/* per-user (stops unlimited resends being used to farm fresh          */
/* 3-attempt windows — the guessing bypass in the original code).      */
/* ------------------------------------------------------------------ */

const registerLimit = limiter({
  key: (req) => `register:ip:${clientIp(req)}`,
  limit: 10,
  windowMs: 15 * 60 * 1000,
  message: "Too many registration attempts from this network. Please try again later.",
});

const sendOtpLimit = limiter({
  key: (req) => `otp:send:${req.user.id}`,
  limit: 5,
  windowMs: 15 * 60 * 1000,
  message: "Too many codes requested. Please wait a few minutes before asking for another.",
});

const verifyOtpLimit = limiter({
  key: (req) => `otp:verify:${req.user.id}`,
  limit: 20,
  windowMs: 15 * 60 * 1000,
  message: "Too many verification attempts. Please wait a few minutes.",
});

/** Maps a verifyChallenge outcome onto an HTTP response. */
function respondToOtpOutcome(res, outcome, onSuccess) {
  switch (outcome.result) {
    case RESULT.OK:
      return onSuccess();
    case RESULT.WRONG_CODE:
      return res.status(400).json({
        verified: false,
        error: "wrong_code",
        attemptsLeft: outcome.attemptsLeft,
        message: "Incorrect code. Please try again.",
      });
    case RESULT.MAX_ATTEMPTS:
      return res.status(429).json({
        verified: false,
        error: "max_attempts",
        message: "Maximum attempts reached. Please request a new code.",
      });
    case RESULT.EXPIRED:
      return res
        .status(410)
        .json({ verified: false, error: "expired", message: "This code has expired." });
    case RESULT.ALREADY_USED:
      return res
        .status(409)
        .json({ verified: false, error: "already_used", message: "This code was already used." });
    default:
      return res
        .status(404)
        .json({ verified: false, error: "not_found", message: "Challenge not found." });
  }
}

/* ------------------------------------------------------------------ */
/* POST /api/register                                                  */
/* ------------------------------------------------------------------ */
router.post("/register", registerLimit, async (req, res, next) => {
  try {
    const { fullName, email, mobile, password } = req.body || {};
    const { valid, errors } = validateRegistration({ fullName, email, mobile, password });

    if (!valid) {
      return res.status(400).json({ error: "validation_failed", fields: errors });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const existing = await users.findByEmail(normalizedEmail);

    if (existing && existing.registration_complete) {
      return res.status(409).json({
        error: "account_exists",
        message: "An account with this email already exists. Please log in instead.",
      });
    }

    // An abandoned half-finished signup may be restarted; a finished one may not.
    const user = existing
      ? await users.resetIncompleteUser(existing.id, { fullName, mobile, password })
      : await users.createUser({ fullName, email: normalizedEmail, mobile, password });

    const { record } = await createChallenge({
      userId: user.id,
      channel: "email",
      purpose: "register-email",
      destination: user.email,
    });

    // From here on, identity travels in this cookie — not in the body.
    issueRegistrationCookie(res, user.id);

    return res.status(201).json({
      message: "Account created. Verify your email to continue.",
      userId: user.id,
      ...challengeResponse(record),
    });
  } catch (err) {
    if (err.code === "delivery_failed") {
      return res.status(502).json({
        error: "delivery_failed",
        message: "We could not send the verification email. Please try again in a moment.",
      });
    }
    return next(err);
  }
});

/* ------------------------------------------------------------------ */
/* POST /api/send-email-otp — resend                                   */
/* ------------------------------------------------------------------ */
router.post("/send-email-otp", requireRegistrationSession, sendOtpLimit, async (req, res, next) => {
  try {
    const { record } = await createChallenge({
      userId: req.user.id,
      channel: "email",
      purpose: "register-email",
      destination: req.user.email,
    });
    return res.json({ message: "OTP sent to your email.", ...challengeResponse(record) });
  } catch (err) {
    if (err.code === "delivery_failed") {
      return res
        .status(502)
        .json({ error: "delivery_failed", message: "Could not send the email. Try again shortly." });
    }
    return next(err);
  }
});

/* ------------------------------------------------------------------ */
/* POST /api/verify-email-otp                                          */
/* ------------------------------------------------------------------ */
router.post(
  "/verify-email-otp",
  requireRegistrationSession,
  verifyOtpLimit,
  async (req, res, next) => {
    try {
      const outcome = await verifyChallenge({
        challengeId: req.body?.challengeId,
        userId: req.user.id, // from the cookie, NOT the body
        purpose: "register-email",
        channel: "email",
        otp: req.body?.otp,
      });

      return respondToOtpOutcome(res, outcome, async () => {
        await users.markEmailVerified(req.user.id);
        return res.json({ verified: true, message: "Email verified." });
      });
    } catch (err) {
      return next(err);
    }
  }
);

/* ------------------------------------------------------------------ */
/* POST /api/send-sms-otp                                              */
/* ------------------------------------------------------------------ */
router.post("/send-sms-otp", requireRegistrationSession, sendOtpLimit, async (req, res, next) => {
  try {
    if (!req.user.email_verified) {
      return res
        .status(400)
        .json({ error: "email_not_verified", message: "Verify your email first." });
    }

    const { record } = await createChallenge({
      userId: req.user.id,
      channel: "sms",
      purpose: "register-sms",
      destination: req.user.mobile,
    });

    return res.json({
      message: "OTP sent to your mobile.",
      ...challengeResponse(record),
    });
  } catch (err) {
    if (err.code === "delivery_failed") {
      return res
        .status(502)
        .json({ error: "delivery_failed", message: "Could not send the SMS. Try again shortly." });
    }
    return next(err);
  }
});

/* ------------------------------------------------------------------ */
/* POST /api/verify-sms-otp                                            */
/* ------------------------------------------------------------------ */
router.post("/verify-sms-otp", requireRegistrationSession, verifyOtpLimit, async (req, res, next) => {
  try {
    const outcome = await verifyChallenge({
      challengeId: req.body?.challengeId,
      userId: req.user.id,
      purpose: "register-sms",
      channel: "sms",
      otp: req.body?.otp,
    });

    return respondToOtpOutcome(res, outcome, async () => {
      await users.markMobileVerified(req.user.id);
      return res.json({ verified: true, message: "Mobile number verified." });
    });
  } catch (err) {
    return next(err);
  }
});

/* ------------------------------------------------------------------ */
/* POST /api/mfa/setup   — ENROLLMENT                                  */
/* { method: 'authenticator' | 'sms' | 'email' }                       */
/*                                                                     */
/* Enrollment is deliberately separate from verification: this issues  */
/* the secret/code, /mfa/verify proves the user holds it. MFA is only  */
/* switched on after that proof.                                       */
/* ------------------------------------------------------------------ */
router.post("/mfa/setup", requireRegistrationSession, sendOtpLimit, async (req, res, next) => {
  try {
    const { method } = req.body || {};
    const user = req.user;

    if (!user.email_verified || !user.mobile_verified) {
      return res
        .status(400)
        .json({ error: "not_ready", message: "Verify email and mobile before setting up MFA." });
    }

    if (method === "authenticator") {
      const secret = mfa.generateSecret();
      await users.setTotpSecret(user.id, secret);

      const uri = mfa.buildOtpAuthUri(user.email, secret);
      const qrDataUrl = await mfa.generateQrDataUrl(uri);
      // Shown once, at enrollment, so the user can type it if the camera
      // fails. It is never returned by any other endpoint.
      const setupKey = secret.match(/.{1,4}/g).join(" ");

      return res.json({
        method,
        qrDataUrl,
        setupKey,
        issuer: mfa.ISSUER,
        accountLabel: user.email,
      });
    }

    if (method === "sms" || method === "email") {
      await users.setMfaMethod(user.id, method);
      const { record } = await createChallenge({
        userId: user.id,
        channel: method === "sms" ? "sms" : "email",
        purpose: `mfa-${method}`,
        destination: method === "sms" ? user.mobile : user.email,
      });
      return res.json({ method, ...challengeResponse(record) });
    }

    return res.status(400).json({ error: "invalid_method" });
  } catch (err) {
    if (err.code === "delivery_failed") {
      return res
        .status(502)
        .json({ error: "delivery_failed", message: "Could not send the code. Try again shortly." });
    }
    return next(err);
  }
});

/* ------------------------------------------------------------------ */
/* POST /api/mfa/verify  — PROOF, then completion                      */
/* ------------------------------------------------------------------ */
router.post("/mfa/verify", requireRegistrationSession, verifyOtpLimit, async (req, res, next) => {
  try {
    const { method, code, challengeId } = req.body || {};
    const user = req.user;

    if (method === "authenticator") {
      if (!user.totp_secret) return res.status(400).json({ error: "not_set_up" });

      if (user.totp_attempts >= MAX_ATTEMPTS) {
        return res.status(429).json({
          verified: false,
          error: "max_attempts",
          message: "Maximum attempts reached. Please set up your authenticator again.",
        });
      }

      if (!mfa.verifyToken(String(code || "").trim(), user.totp_secret)) {
        const { totp_attempts } = await users.bumpTotpAttempts(user.id);
        const attemptsLeft = MAX_ATTEMPTS - totp_attempts;
        if (attemptsLeft <= 0) {
          return res.status(429).json({
            verified: false,
            error: "max_attempts",
            message: "Maximum attempts reached. Please set up your authenticator again.",
          });
        }
        return res.status(400).json({
          verified: false,
          error: "wrong_code",
          attemptsLeft,
          message: "Invalid code. Please try again.",
        });
      }

      await users.completeRegistration(user.id);
      clearRegistrationCookie(res);
      return res.json({
        verified: true,
        registrationComplete: true,
        message: "MFA enabled. Registration complete.",
      });
    }

    if (method === "sms" || method === "email") {
      const outcome = await verifyChallenge({
        challengeId,
        userId: user.id,
        purpose: `mfa-${method}`,
        channel: method === "sms" ? "sms" : "email",
        otp: code,
      });

      return respondToOtpOutcome(res, outcome, async () => {
        await users.completeRegistration(user.id);
        clearRegistrationCookie(res);
        return res.json({
          verified: true,
          registrationComplete: true,
          message: "MFA enabled. Registration complete.",
        });
      });
    }

    return res.status(400).json({ error: "invalid_method" });
  } catch (err) {
    return next(err);
  }
});

/* ------------------------------------------------------------------ */
/* GET /api/registration-status                                        */
/*                                                                     */
/* Replaces the old GET /api/user/:userId, which let anyone read any   */
/* user's email and mobile just by supplying an id. This one only ever */
/* reports on the caller's own in-progress signup.                     */
/* ------------------------------------------------------------------ */
router.get("/registration-status", requireRegistrationSession, (req, res) => {
  return res.json(users.publicUser(req.user));
});

module.exports = router;
