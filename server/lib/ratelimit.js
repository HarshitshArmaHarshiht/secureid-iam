/**
 * Fixed-window rate limiting, stored in PostgreSQL.
 *
 * Why not express-rate-limit? Its default store is process memory. Vercel
 * runs many isolated instances and cold-starts them constantly, so an
 * in-memory counter resets under load — exactly when it matters. A shared
 * DB counter is the only thing that actually holds across instances.
 *
 * The increment is a single atomic UPSERT, so concurrent requests cannot
 * race past the limit.
 */

const { queryOne } = require("../db/pool");

/**
 * @param key      stable bucket identity, e.g. "otp:send:<userId>"
 * @param limit    max hits allowed inside the window
 * @param windowMs window length in milliseconds
 * @returns {{allowed:boolean, remaining:number, retryAfterMs:number}}
 */
async function hit(key, limit, windowMs) {
  // Floor "now" to the start of its window so every instance agrees on the bucket.
  const windowStartMs = Math.floor(Date.now() / windowMs) * windowMs;
  const windowStart = new Date(windowStartMs);

  const row = await queryOne(
    `insert into rate_limits (bucket_key, window_start, hits)
     values ($1, $2, 1)
     on conflict (bucket_key, window_start)
     do update set hits = rate_limits.hits + 1
     returning hits`,
    [key, windowStart]
  );

  const hits = row.hits;
  const retryAfterMs = windowStartMs + windowMs - Date.now();

  return {
    allowed: hits <= limit,
    remaining: Math.max(0, limit - hits),
    retryAfterMs: Math.max(0, retryAfterMs),
  };
}

/**
 * Express middleware factory.
 * `keyFn` derives the bucket from the request — usually IP, user id, or both.
 */
function limiter({ key, limit, windowMs, message }) {
  return async (req, res, next) => {
    try {
      const bucket = typeof key === "function" ? key(req) : key;
      if (!bucket) return next();

      const result = await hit(bucket, limit, windowMs);
      res.setHeader("X-RateLimit-Limit", String(limit));
      res.setHeader("X-RateLimit-Remaining", String(result.remaining));

      if (!result.allowed) {
        const retryAfterSec = Math.ceil(result.retryAfterMs / 1000);
        res.setHeader("Retry-After", String(retryAfterSec));
        return res.status(429).json({
          error: "rate_limited",
          retryAfterSeconds: retryAfterSec,
          message: message || `Too many requests. Try again in ${retryAfterSec}s.`,
        });
      }
      return next();
    } catch (err) {
      // A limiter outage must not take the whole API down with it.
      console.error("[ratelimit] failed open:", err.message);
      return next();
    }
  };
}

/** Client IP, honouring Vercel's proxy header. */
function clientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd.length) return fwd.split(",")[0].trim();
  return req.ip || req.socket?.remoteAddress || "unknown";
}

module.exports = { hit, limiter, clientIp };
