/**
 * User repository. All SQL touching the users table lives here.
 */

const bcrypt = require("bcryptjs");
const { query, queryOne } = require("../db/pool");

const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 10);

async function hashPassword(plain) {
  return bcrypt.hash(plain, BCRYPT_ROUNDS);
}

async function checkPassword(plain, hash) {
  if (!hash) {
    // Still burn a comparison so a missing user and a wrong password take
    // the same time — otherwise response timing enumerates valid emails.
    await bcrypt.compare(String(plain || ""), "$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidin");
    return false;
  }
  return bcrypt.compare(String(plain || ""), hash);
}

async function findByEmail(email) {
  return queryOne(`select * from users where email = $1`, [String(email).trim().toLowerCase()]);
}

async function findById(id) {
  if (!id) return null;
  // Guard against a malformed id reaching Postgres as a uuid cast error.
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(id))) {
    return null;
  }
  return queryOne(`select * from users where id = $1`, [id]);
}

async function createUser({ fullName, email, mobile, password }) {
  const passwordHash = await hashPassword(password);
  return queryOne(
    `insert into users (full_name, email, mobile, password_hash)
     values ($1, $2, $3, $4)
     returning *`,
    [String(fullName).trim(), String(email).trim().toLowerCase(), String(mobile).trim(), passwordHash]
  );
}

/**
 * Replace an abandoned, never-completed registration with a fresh one.
 * A *completed* account is never overwritten — the caller returns 409.
 */
async function resetIncompleteUser(id, { fullName, mobile, password }) {
  const passwordHash = await hashPassword(password);
  return queryOne(
    `update users
        set full_name = $2, mobile = $3, password_hash = $4,
            email_verified = false, mobile_verified = false,
            mfa_enabled = false, mfa_method = null,
            totp_secret = null, totp_attempts = 0,
            registration_complete = false, updated_at = now()
      where id = $1
      returning *`,
    [id, String(fullName).trim(), String(mobile).trim(), passwordHash]
  );
}

async function markEmailVerified(id) {
  return queryOne(
    `update users set email_verified = true, updated_at = now() where id = $1 returning *`,
    [id]
  );
}

async function markMobileVerified(id) {
  return queryOne(
    `update users set mobile_verified = true, updated_at = now() where id = $1 returning *`,
    [id]
  );
}

async function setTotpSecret(id, secret) {
  return queryOne(
    `update users
        set totp_secret = $2, mfa_method = 'authenticator', totp_attempts = 0, updated_at = now()
      where id = $1 returning *`,
    [id, secret]
  );
}

async function setMfaMethod(id, method) {
  return queryOne(
    `update users set mfa_method = $2, updated_at = now() where id = $1 returning *`,
    [id, method]
  );
}

async function bumpTotpAttempts(id) {
  return queryOne(
    `update users set totp_attempts = totp_attempts + 1, updated_at = now()
      where id = $1 returning totp_attempts`,
    [id]
  );
}

/* ------------------------------------------------------------------ */
/* Temporary account lockout                                           */
/*                                                                     */
/* Distinct from rate limiting: the limiter throttles request VOLUME,  */
/* this locks a specific account after repeated WRONG PASSWORDS. Both  */
/* matter — a slow, distributed guessing attack stays under any rate   */
/* limit but still trips the lockout.                                  */
/* ------------------------------------------------------------------ */

const MAX_FAILED_LOGINS = Number(process.env.MAX_FAILED_LOGINS || 5);
const LOCKOUT_MINUTES = Number(process.env.LOCKOUT_MINUTES || 15);

function lockoutState(user) {
  if (!user?.locked_until) return { locked: false, secondsRemaining: 0 };
  const remainingMs = new Date(user.locked_until).getTime() - Date.now();
  return remainingMs > 0
    ? { locked: true, secondsRemaining: Math.ceil(remainingMs / 1000) }
    : { locked: false, secondsRemaining: 0 };
}

/** Count a failed password attempt; lock the account once the cap is hit. */
async function recordFailedLogin(id) {
  return queryOne(
    `update users
        set failed_login_attempts = failed_login_attempts + 1,
            locked_until = case
              when failed_login_attempts + 1 >= $2
              then now() + ($3 || ' minutes')::interval
              else locked_until
            end,
            updated_at = now()
      where id = $1
      returning failed_login_attempts, locked_until`,
    [id, MAX_FAILED_LOGINS, String(LOCKOUT_MINUTES)]
  );
}

/** Clear the counter after a successful password check. */
async function clearFailedLogins(id) {
  return queryOne(
    `update users
        set failed_login_attempts = 0, locked_until = null, updated_at = now()
      where id = $1 and (failed_login_attempts > 0 or locked_until is not null)
      returning id`,
    [id]
  );
}

async function completeRegistration(id) {
  return queryOne(
    `update users
        set mfa_enabled = true, registration_complete = true,
            totp_attempts = 0, updated_at = now()
      where id = $1 returning *`,
    [id]
  );
}

/**
 * The ONLY user shape that may cross the network.
 * Deliberately omits password_hash, totp_secret and totp_attempts.
 */
function publicUser(user) {
  if (!user) return null;
  return {
    userId: user.id,
    fullName: user.full_name,
    email: user.email,
    mobile: user.mobile,
    emailVerified: user.email_verified,
    mobileVerified: user.mobile_verified,
    mfaEnabled: user.mfa_enabled,
    mfaMethod: user.mfa_method,
    registrationComplete: user.registration_complete,
    createdAt: user.created_at,
  };
}

module.exports = {
  hashPassword,
  checkPassword,
  findByEmail,
  findById,
  createUser,
  resetIncompleteUser,
  markEmailVerified,
  markMobileVerified,
  setTotpSecret,
  setMfaMethod,
  bumpTotpAttempts,
  completeRegistration,
  publicUser,
  BCRYPT_ROUNDS,
  lockoutState,
  recordFailedLogin,
  clearFailedLogins,
  MAX_FAILED_LOGINS,
  LOCKOUT_MINUTES,
};
