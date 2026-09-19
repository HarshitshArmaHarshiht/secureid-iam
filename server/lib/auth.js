/**
 * Authentication: JWTs carried in HttpOnly cookies, backed by a sessions
 * table so logout can genuinely revoke.
 *
 * Two distinct cookies, deliberately separate:
 *
 *   reg_session  — short-lived, issued at POST /api/register. It carries
 *                  the userId through the multi-step signup. This is what
 *                  closes the "verify my OTP but send your userId" hole:
 *                  the server reads the user identity from this signed
 *                  cookie and ignores any userId in the request body.
 *
 *   sid          — the real login session, issued only after password +
 *                  MFA both pass. Carries a jti matching a sessions row.
 *
 * Tokens live in HttpOnly cookies rather than localStorage so page
 * JavaScript (and therefore any XSS payload) cannot read them.
 */

const jwt = require("jsonwebtoken");
const { query, queryOne } = require("../db/pool");
const { findById, publicUser } = require("./users");

const JWT_SECRET = process.env.JWT_SECRET;
const IS_PROD = process.env.NODE_ENV === "production";

const REG_COOKIE = "reg_session";
const SID_COOKIE = "sid";

const REG_TTL_MS = 30 * 60 * 1000; // 30 min — plenty for a signup, short enough to matter
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_HOURS || 12) * 60 * 60 * 1000;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error(
    "JWT_SECRET must be set to a random string of at least 32 characters. " +
      "Generate one with:  node -e \"console.log(require('crypto').randomBytes(48).toString('base64url'))\""
  );
}

function cookieOptions(maxAgeMs) {
  return {
    httpOnly: true,
    // Secure cookies require HTTPS; localhost dev is plain HTTP.
    secure: IS_PROD,
    // Lax still sends the cookie on top-level navigation back to the app,
    // while blocking it on cross-site POSTs — our CSRF baseline.
    sameSite: "lax",
    path: "/",
    maxAge: maxAgeMs,
  };
}

/* ------------------------------------------------------------------ */
/* Registration session                                                */
/* ------------------------------------------------------------------ */

function issueRegistrationCookie(res, userId) {
  const token = jwt.sign({ sub: userId, typ: "reg" }, JWT_SECRET, {
    expiresIn: Math.floor(REG_TTL_MS / 1000),
  });
  res.cookie(REG_COOKIE, token, cookieOptions(REG_TTL_MS));
}

function clearRegistrationCookie(res) {
  res.clearCookie(REG_COOKIE, { ...cookieOptions(0), maxAge: undefined });
}

/** Reads the userId from the signed registration cookie. Null if absent/invalid. */
function registrationUserId(req) {
  const token = req.cookies?.[REG_COOKIE];
  if (!token) return null;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return payload.typ === "reg" ? payload.sub : null;
  } catch {
    return null;
  }
}

/**
 * Gate for every step after POST /api/register.
 * Attaches req.user. Never trusts a userId from the request body.
 */
async function requireRegistrationSession(req, res, next) {
  const userId = registrationUserId(req);
  if (!userId) {
    return res.status(401).json({
      error: "no_registration_session",
      message: "Your signup session expired. Please start again.",
    });
  }
  const user = await findById(userId);
  if (!user) {
    return res.status(401).json({ error: "no_registration_session", message: "Please start again." });
  }
  req.user = user;
  return next();
}

/* ------------------------------------------------------------------ */
/* Login session                                                       */
/* ------------------------------------------------------------------ */

async function createSession(res, user, req) {
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  const session = await queryOne(
    `insert into sessions (user_id, expires_at, user_agent, ip)
     values ($1, $2, $3, $4) returning id`,
    [
      user.id,
      expiresAt,
      String(req.headers["user-agent"] || "").slice(0, 300),
      String(req.headers["x-forwarded-for"] || req.ip || "").split(",")[0].trim().slice(0, 64),
    ]
  );

  const token = jwt.sign({ sub: user.id, jti: session.id, typ: "sid" }, JWT_SECRET, {
    expiresIn: Math.floor(SESSION_TTL_MS / 1000),
  });

  res.cookie(SID_COOKIE, token, cookieOptions(SESSION_TTL_MS));
  return session.id;
}

/**
 * Validates signature + expiry (jwt.verify) AND that the session row is
 * still live. The DB check is what makes logout real.
 */
async function currentUser(req) {
  const token = req.cookies?.[SID_COOKIE];
  if (!token) return null;

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
  if (payload.typ !== "sid" || !payload.jti) return null;

  const session = await queryOne(
    `select id, user_id, expires_at, revoked_at from sessions where id = $1`,
    [payload.jti]
  );
  if (!session) return null;
  if (session.revoked_at) return null;
  if (new Date(session.expires_at).getTime() <= Date.now()) return null;
  if (session.user_id !== payload.sub) return null;

  const user = await findById(payload.sub);
  if (!user) return null;

  return { user, sessionId: session.id };
}

async function requireAuth(req, res, next) {
  const ctx = await currentUser(req);
  if (!ctx) {
    return res.status(401).json({ error: "unauthenticated", message: "Please log in." });
  }
  req.user = ctx.user;
  req.sessionId = ctx.sessionId;
  return next();
}

async function revokeSession(sessionId) {
  if (!sessionId) return;
  await query(`update sessions set revoked_at = now() where id = $1 and revoked_at is null`, [
    sessionId,
  ]);
}

function clearSessionCookie(res) {
  res.clearCookie(SID_COOKIE, { ...cookieOptions(0), maxAge: undefined });
}

module.exports = {
  REG_COOKIE,
  SID_COOKIE,
  SESSION_TTL_MS,
  issueRegistrationCookie,
  clearRegistrationCookie,
  registrationUserId,
  requireRegistrationSession,
  createSession,
  currentUser,
  requireAuth,
  revokeSession,
  clearSessionCookie,
  publicUser,
};
