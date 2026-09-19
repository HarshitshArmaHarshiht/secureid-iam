/**
 * OTP challenge lifecycle, backed by PostgreSQL.
 *
 * SECURITY NOTE — the bug this replaces:
 * The previous in-memory version verified a challengeId and then trusted a
 * *separately supplied* userId, so you could verify your own OTP while
 * passing someone else's id and mark their email verified. Every lookup
 * here is now scoped by (id AND user_id AND purpose AND channel), so a
 * challenge can only ever satisfy the exact user/step it was minted for.
 */

const { query, queryOne, withTransaction } = require("../db/pool");
const { generateOtp, hashOtp, verifyOtpHash, OTP_TTL_MS, MAX_ATTEMPTS } = require("./otp");
const { sendOtpEmail } = require("./mailer");
const { sendOtpSms } = require("./sms");
const { shouldStoreTestOtp } = require("./testing");

const RESULT = {
  OK: "ok",
  NOT_FOUND: "not_found",
  EXPIRED: "expired",
  WRONG_CODE: "wrong_code",
  MAX_ATTEMPTS: "max_attempts",
  ALREADY_USED: "already_used",
};

/** Which channel a purpose is allowed to use. Prevents cross-channel replay. */
const PURPOSE_CHANNEL = {
  "register-email": "email",
  "register-sms": "sms",
  "mfa-email": "email",
  "mfa-sms": "sms",
  "login-mfa": null, // decided by the user's enrolled MFA method
};

/**
 * Create a challenge, persist only its hash, and deliver the code.
 *
 * Any previously-unconsumed challenge for the same (user, purpose) is
 * invalidated first, so a resend genuinely replaces the old code instead
 * of leaving several valid codes in flight.
 */
async function createChallenge({ userId, channel, purpose, destination }) {
  const expected = PURPOSE_CHANNEL[purpose];
  if (expected !== null && expected !== undefined && expected !== channel) {
    throw new Error(`purpose "${purpose}" cannot be delivered over channel "${channel}"`);
  }

  const otp = generateOtp();
  const ttlSeconds = Math.round(OTP_TTL_MS / 1000);

  const record = await withTransaction(async (client) => {
    await client.query(
      `update otp_challenges
          set consumed = true, consumed_at = now()
        where user_id = $1 and purpose = $2 and consumed = false`,
      [userId, purpose]
    );

    // test_otp is NULL unless the TEST-ONLY retrieval API is enabled.
    // With the default configuration no plaintext OTP is ever persisted.
    const testOtp = shouldStoreTestOtp() ? otp : null;

    const { rows } = await client.query(
      `insert into otp_challenges
         (user_id, purpose, channel, destination, otp_hash, expires_at, max_attempts, test_otp)
       values ($1, $2, $3, $4, $5, now() + ($6 || ' milliseconds')::interval, $7, $8)
       returning id, user_id, purpose, channel, destination, expires_at, attempts,
                 max_attempts, consumed`,
      [
        userId,
        purpose,
        channel,
        destination,
        hashOtp(otp),
        String(OTP_TTL_MS),
        MAX_ATTEMPTS,
        testOtp,
      ]
    );
    return rows[0];
  });

  // Delivery happens after the row is committed, so a transport failure
  // can never leave a code "sent" with nothing stored to verify it against.
  try {
    if (channel === "email") {
      await sendOtpEmail(destination, otp, ttlSeconds);
    } else {
      await sendOtpSms(destination, otp, ttlSeconds);
    }
  } catch (err) {
    console.error(`[challenge] ${channel} delivery failed:`, err.message);
    const wrapped = new Error("delivery_failed");
    wrapped.code = "delivery_failed";
    wrapped.channel = channel;
    throw wrapped;
  }

  // The OTP is NEVER returned to the caller. An evaluator retrieves a
  // simulated SMS code through the separate, token-protected test API
  // (server/routes/testing.js), not from this response.
  return { record };
}

/**
 * Verify a submitted OTP.
 *
 * Every one of these must hold: the challenge exists, belongs to THIS
 * user, was minted for THIS purpose and channel, is unconsumed, unexpired,
 * and under the attempt cap. The comparison itself is constant-time.
 */
async function verifyChallenge({ challengeId, userId, purpose, channel, otp }) {
  if (!challengeId || !userId) return { result: RESULT.NOT_FOUND };

  // Row-level lock so two concurrent submissions cannot both consume the
  // same challenge or both slip past the attempt counter.
  return withTransaction(async (client) => {
    const { rows } = await client.query(
      `select * from otp_challenges
        where id = $1 and user_id = $2 and purpose = $3 and channel = $4
        for update`,
      [challengeId, userId, purpose, channel]
    );

    const record = rows[0];
    if (!record) return { result: RESULT.NOT_FOUND };
    if (record.consumed) return { result: RESULT.ALREADY_USED };
    if (record.attempts >= record.max_attempts) return { result: RESULT.MAX_ATTEMPTS };
    if (new Date(record.expires_at).getTime() <= Date.now()) return { result: RESULT.EXPIRED };

    if (!verifyOtpHash(String(otp || ""), record.otp_hash)) {
      const { rows: bumped } = await client.query(
        `update otp_challenges set attempts = attempts + 1
          where id = $1 returning attempts, max_attempts`,
        [record.id]
      );
      const attemptsLeft = bumped[0].max_attempts - bumped[0].attempts;
      return attemptsLeft <= 0
        ? { result: RESULT.MAX_ATTEMPTS }
        : { result: RESULT.WRONG_CODE, attemptsLeft };
    }

    // Single-use: consumed in the same transaction that validated it.
    await client.query(
      `update otp_challenges set consumed = true, consumed_at = now() where id = $1`,
      [record.id]
    );

    return { result: RESULT.OK, record };
  });
}

function msLeft(record) {
  return Math.max(0, new Date(record.expires_at).getTime() - Date.now());
}

/** Shape returned to the client. Deliberately contains no OTP material. */
function challengeResponse(record, extra = {}) {
  return {
    challengeId: record.id,
    channel: record.channel,
    expiresInMs: msLeft(record),
    maxAttempts: record.max_attempts,
    ...extra,
  };
}

module.exports = { createChallenge, verifyChallenge, challengeResponse, RESULT, msLeft };
