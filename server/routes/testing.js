/**
 * ============================================================
 *  TEST-ONLY ROUTES — NOT PART OF THE PRODUCT API
 * ============================================================
 *
 * Mounted by server/index.js only when server/lib/testing.js reports
 * ENABLED (flag on + token set + SMS_MODE=mock). With the default
 * configuration this file is never reached.
 *
 * Purpose: let an evaluator read back a SIMULATED SMS code so the mobile
 * verification step can be completed on a deployed instance, where the
 * server console is not visible.
 *
 *   GET /api/test/otp?challengeId=<uuid>
 *   GET /api/test/otp?mobile=9876543210
 *   GET /api/test/otp?email=someone@example.com
 *
 *   Header:  x-test-token: <TEST_OTP_TOKEN>
 *            (or  Authorization: Bearer <TEST_OTP_TOKEN>)
 *
 * Returns the most recent matching challenge. Only ever returns a code
 * that was generated while this API was enabled; anything older has a
 * NULL test_otp and reports why.
 */

const express = require("express");
const { query } = require("../db/pool");
const { tokenMatches } = require("../lib/testing");

const router = express.Router();

/** Every route below is behind the token. */
router.use((req, res, next) => {
  const header = req.get("x-test-token") || "";
  const bearer = (req.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const supplied = header || bearer;

  if (!tokenMatches(supplied)) {
    // Deliberately vague — do not confirm whether the endpoint exists.
    return res.status(404).json({ error: "not_found" });
  }
  // Belt and braces: keep this out of caches and crawlers.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Robots-Tag", "noindex");
  return next();
});

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

router.get("/otp", async (req, res, next) => {
  try {
    const { challengeId, mobile, email } = req.query;

    let sql;
    let params;

    if (challengeId) {
      if (!UUID_RE.test(String(challengeId))) {
        return res.status(400).json({ error: "invalid_challenge_id" });
      }
      sql = `select c.*, u.email, u.mobile
               from otp_challenges c
               join users u on u.id = c.user_id
              where c.id = $1`;
      params = [challengeId];
    } else if (mobile) {
      sql = `select c.*, u.email, u.mobile
               from otp_challenges c
               join users u on u.id = c.user_id
              where u.mobile = $1 and c.channel = 'sms'
              order by c.created_at desc
              limit 1`;
      params = [String(mobile).trim()];
    } else if (email) {
      sql = `select c.*, u.email, u.mobile
               from otp_challenges c
               join users u on u.id = c.user_id
              where u.email = $1
              order by c.created_at desc
              limit 1`;
      params = [String(email).trim().toLowerCase()];
    } else {
      return res.status(400).json({
        error: "missing_query",
        message: "Provide one of: challengeId, mobile, email.",
      });
    }

    const { rows } = await query(sql, params);
    const record = rows[0];

    if (!record) return res.status(404).json({ error: "challenge_not_found" });

    if (!record.test_otp) {
      return res.status(409).json({
        error: "otp_not_recorded",
        message:
          "This challenge was created while the test API was disabled, so only its hash exists. " +
          "Request a new code and try again.",
      });
    }

    return res.json({
      _warning: "TEST-ONLY endpoint. Never enable this for real user accounts.",
      challengeId: record.id,
      userId: record.user_id,
      purpose: record.purpose,
      channel: record.channel,
      destination: record.destination,
      otp: record.test_otp,
      attempts: record.attempts,
      maxAttempts: record.max_attempts,
      consumed: record.consumed,
      expiresAt: record.expires_at,
      expired: new Date(record.expires_at).getTime() <= Date.now(),
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
