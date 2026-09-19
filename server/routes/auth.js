/**
 * Login journey:
 *   POST /api/login       → password check, then an MFA challenge
 *   POST /api/login/mfa   → MFA proof, then a real session
 *   POST /api/logout      → revokes the session row
 *   GET  /api/me          → the current user, from the validated session
 *
 * Login is two steps on purpose. Passing the password alone does NOT get
 * you a session cookie — it gets you a short-lived "pending MFA" token.
 * Only /api/login/mfa issues `sid`.
 */

const express = require("express");
const jwt = require("jsonwebtoken");

const users = require("../lib/users");
const mfa = require("../lib/mfa");
const { createChallenge, verifyChallenge, challengeResponse, RESULT } = require("../lib/challenge");
const { queryOne } = require("../db/pool");
const { MAX_ATTEMPTS } = require("../lib/otp");
const { limiter, clientIp } = require("../lib/ratelimit");
const {
  createSession,
  requireAuth,
  currentUser,
  revokeSession,
  clearSessionCookie,
  publicUser,
} = require("../lib/auth");

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;
const PENDING_TTL_SEC = 10 * 60; // 10 minutes to finish the MFA step
const ACCESS_TTL_SEC = Number(process.env.ACCESS_TOKEN_TTL_MINUTES || 15) * 60;

/* ------------------------------------------------------------------ */
/* Rate limits — per IP and per account.                               */
/* The per-account bucket is what stops a botnet spreading a password  */
/* spray across many IPs against one victim.                           */
/* ------------------------------------------------------------------ */

const loginIpLimit = limiter({
  key: (req) => `login:ip:${clientIp(req)}`,
  limit: 20,
  windowMs: 15 * 60 * 1000,
  message: "Too many login attempts from this network. Please try again later.",
});

const loginEmailLimit = limiter({
  key: (req) => {
    const email = String(req.body?.email || "").trim().toLowerCase();
    return email ? `login:email:${email}` : null;
  },
  limit: 8,
  windowMs: 15 * 60 * 1000,
  message: "Too many login attempts for this account. Please try again later.",
});

/* ------------------------------------------------------------------ */
/* POST /api/login — step 1: password                                  */
/* ------------------------------------------------------------------ */
router.post("/login", loginIpLimit, loginEmailLimit, async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "validation_failed", message: "Email and password are required." });
    }

    const user = await users.findByEmail(email);

    // Locked accounts are refused before the password is even considered.
    const lock = users.lockoutState(user);
    if (lock.locked) {
      return res.status(423).json({
        error: "account_locked",
        retryAfterSeconds: lock.secondsRemaining,
        message: `Too many failed attempts. Try again in ${Math.ceil(
          lock.secondsRemaining / 60
        )} minute(s).`,
      });
    }

    // checkPassword burns a bcrypt compare even when the user is missing,
    // so response timing cannot be used to enumerate registered emails.
    const passwordOk = await users.checkPassword(password, user?.password_hash);

    // One identical message for "no such user" and "wrong password".
    if (!user || !passwordOk) {
      if (user) {
        const state = await users.recordFailedLogin(user.id);
        // Tell the user the moment the account actually locks, but never
        // reveal a running count — that would confirm the email exists.
        if (state?.locked_until && new Date(state.locked_until).getTime() > Date.now()) {
          return res.status(423).json({
            error: "account_locked",
            message: `Too many failed attempts. This account is locked for ${users.LOCKOUT_MINUTES} minutes.`,
          });
        }
      }
      return res
        .status(401)
        .json({ error: "invalid_credentials", message: "Incorrect email or password." });
    }

    // Correct password — reset the failure counter.
    await users.clearFailedLogins(user.id);

    if (!user.registration_complete) {
      return res.status(403).json({
        error: "registration_incomplete",
        message: "Please finish creating your account before logging in.",
      });
    }

    // Password is correct — but this is NOT a session yet.
    const pendingToken = jwt.sign({ sub: user.id, typ: "pending_mfa" }, JWT_SECRET, {
      expiresIn: PENDING_TTL_SEC,
    });

    const method = user.mfa_method || "authenticator";

    if (method === "authenticator") {
      return res.json({
        mfaRequired: true,
        method,
        pendingToken,
        message: "Enter the code from your authenticator app.",
      });
    }

    // SMS/email MFA: send a fresh code now.
    const { record } = await createChallenge({
      userId: user.id,
      channel: method === "sms" ? "sms" : "email",
      purpose: "login-mfa",
      destination: method === "sms" ? user.mobile : user.email,
    });

    return res.json({
      mfaRequired: true,
      method,
      pendingToken,
      ...challengeResponse(record),
      message: `We sent a code to your ${method === "sms" ? "mobile" : "email"}.`,
    });
  } catch (err) {
    if (err.code === "delivery_failed") {
      return res
        .status(502)
        .json({ error: "delivery_failed", message: "Could not send your code. Try again shortly." });
    }
    return next(err);
  }
});

/* ------------------------------------------------------------------ */
/* POST /api/login/mfa — step 2: MFA proof → session                   */
/* ------------------------------------------------------------------ */
/*
 * Two paths, one handler. /api/verify-login-otp is the name the assignment
 * specifies; /api/login/mfa is the name the frontend already calls. They
 * are the same endpoint, not two implementations.
 */
router.post(["/verify-login-otp", "/login/mfa"], loginIpLimit, async (req, res, next) => {
  try {
    const { pendingToken, code, challengeId } = req.body || {};

    let payload;
    try {
      payload = jwt.verify(String(pendingToken || ""), JWT_SECRET);
    } catch {
      return res.status(401).json({
        error: "pending_expired",
        message: "Your login attempt expired. Please sign in again.",
      });
    }
    if (payload.typ !== "pending_mfa") {
      return res.status(401).json({ error: "pending_expired", message: "Please sign in again." });
    }

    const user = await users.findById(payload.sub);
    if (!user) {
      return res.status(401).json({ error: "pending_expired", message: "Please sign in again." });
    }

    const method = user.mfa_method || "authenticator";

    if (method === "authenticator") {
      if (user.totp_attempts >= MAX_ATTEMPTS) {
        return res.status(429).json({
          error: "max_attempts",
          message: "Too many incorrect codes. Please try again later.",
        });
      }

      if (!mfa.verifyToken(String(code || "").trim(), user.totp_secret)) {
        const { totp_attempts } = await users.bumpTotpAttempts(user.id);
        const attemptsLeft = MAX_ATTEMPTS - totp_attempts;
        return res.status(400).json({
          error: attemptsLeft <= 0 ? "max_attempts" : "wrong_code",
          attemptsLeft: Math.max(0, attemptsLeft),
          message: "Invalid code. Please try again.",
        });
      }

      await users.completeRegistration(user.id); // resets totp_attempts to 0
      await createSession(res, user, req);
      return res.json({ authenticated: true, user: publicUser(user) });
    }

    // SMS / email MFA
    const outcome = await verifyChallenge({
      challengeId,
      userId: user.id,
      purpose: "login-mfa",
      channel: method === "sms" ? "sms" : "email",
      otp: code,
    });

    switch (outcome.result) {
      case RESULT.OK:
        await createSession(res, user, req);
        return res.json({ authenticated: true, user: publicUser(user) });
      case RESULT.WRONG_CODE:
        return res.status(400).json({
          error: "wrong_code",
          attemptsLeft: outcome.attemptsLeft,
          message: "Incorrect code. Please try again.",
        });
      case RESULT.MAX_ATTEMPTS:
        return res
          .status(429)
          .json({ error: "max_attempts", message: "Maximum attempts reached. Please sign in again." });
      case RESULT.EXPIRED:
        return res.status(410).json({ error: "expired", message: "This code has expired." });
      case RESULT.ALREADY_USED:
        return res.status(409).json({ error: "already_used", message: "This code was already used." });
      default:
        return res.status(404).json({ error: "not_found", message: "Challenge not found." });
    }
  } catch (err) {
    return next(err);
  }
});

/* ------------------------------------------------------------------ */
/* GET /api/me                                                         */
/*                                                                     */
/* Identity comes from the validated session only — signature, expiry  */
/* and a live (unrevoked) sessions row. Returns publicUser(), which    */
/* omits password_hash, totp_secret and totp_attempts.                 */
/* ------------------------------------------------------------------ */
router.get("/me", requireAuth, (req, res) => {
  return res.json({ authenticated: true, user: publicUser(req.user) });
});

/* ------------------------------------------------------------------ */
/* POST /api/token — short-lived API access token                      */
/*                                                                     */
/* Exchanges the logged-in session cookie for a bearer token, for       */
/* calling the API from something that is not the browser (curl, a      */
/* script, a mobile client).                                            */
/*                                                                     */
/* Short-lived by design: it is carried in an Authorization header      */
/* rather than an HttpOnly cookie, so it is more exposed than `sid`.    */
/* It carries the session's jti, so logging out kills it too.           */
/*                                                                     */
/* The token is returned in the response body and NOT persisted by the  */
/* frontend — nothing in public/ writes it to localStorage or           */
/* sessionStorage. The browser app authenticates with its cookie and    */
/* has no need for this token at all.                                   */
/* ------------------------------------------------------------------ */
router.post("/token", requireAuth, (req, res) => {
  const token = jwt.sign(
    { sub: req.user.id, jti: req.sessionId, typ: "access" },
    JWT_SECRET,
    { expiresIn: ACCESS_TTL_SEC }
  );

  return res.json({
    tokenType: "Bearer",
    accessToken: token,
    expiresIn: ACCESS_TTL_SEC,
    note: "Send as: Authorization: Bearer <accessToken>. Do not store this in localStorage.",
  });
});

/* ------------------------------------------------------------------ */
/* GET /api/protected — an example resource behind the bearer token    */
/*                                                                     */
/* Validates server-side: signature (JWT_SECRET), expiry, token type,   */
/* and that the underlying session row is still live. A token minted    */
/* before logout is therefore rejected after it.                        */
/* ------------------------------------------------------------------ */
router.get("/protected", async (req, res, next) => {
  try {
    const header = req.get("authorization") || "";
    const match = header.match(/^Bearer\s+(.+)$/i);

    if (!match) {
      return res.status(401).json({
        error: "missing_token",
        message: "Send an Authorization: Bearer <token> header.",
      });
    }

    let payload;
    try {
      payload = jwt.verify(match[1], JWT_SECRET);
    } catch (err) {
      // jwt.verify covers both a bad signature and an expired token.
      return res.status(401).json({
        error: err.name === "TokenExpiredError" ? "token_expired" : "invalid_token",
        message: "That token is not valid.",
      });
    }

    // A session cookie JWT must not be usable as a bearer token, and vice versa.
    if (payload.typ !== "access") {
      return res.status(401).json({ error: "invalid_token", message: "Wrong token type." });
    }

    const session = await queryOne(
      `select revoked_at, expires_at from sessions where id = $1`,
      [payload.jti]
    );
    if (!session || session.revoked_at || new Date(session.expires_at).getTime() <= Date.now()) {
      return res
        .status(401)
        .json({ error: "session_revoked", message: "This session is no longer active." });
    }

    const user = await users.findById(payload.sub);
    if (!user) return res.status(401).json({ error: "invalid_token" });

    return res.json({
      message: "Access granted. This resource requires a valid bearer token.",
      user: publicUser(user),
      tokenExpiresAt: new Date(payload.exp * 1000).toISOString(),
    });
  } catch (err) {
    return next(err);
  }
});

/* ------------------------------------------------------------------ */
/* POST /api/logout                                                    */
/*                                                                     */
/* Revokes the session row, so the JWT stops working immediately even  */
/* though it has not expired. Clearing the cookie alone would not do   */
/* that — a copied token would still be accepted.                      */
/* ------------------------------------------------------------------ */
router.post("/logout", async (req, res, next) => {
  try {
    const ctx = await currentUser(req);
    if (ctx) await revokeSession(ctx.sessionId);
    clearSessionCookie(res);
    // Idempotent: logging out when already logged out is a success.
    return res.json({ ok: true, message: "Logged out." });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
