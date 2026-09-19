const path = require("path");

// Resolve .env relative to the project, not the current working directory,
// so `node server/index.js` works from anywhere.
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const registerRoutes = require("./routes/register");
const authRoutes = require("./routes/auth");
const { describeEmailConfig } = require("./lib/mailer");
const { describeSmsConfig } = require("./lib/sms");
const testing = require("./lib/testing");

const app = express();

// Vercel terminates TLS upstream; without this, req.ip is the proxy's
// address and `secure` cookies are never set.
app.set("trust proxy", 1);

/* ------------------------------------------------------------------ */
/* Security headers                                                    */
/* ------------------------------------------------------------------ */
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        // The MFA QR code arrives as a data: URL from our own API.
        imgSrc: ["'self'", "data:"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    // Allows the favicon data: URL to render.
    crossOriginEmbedderPolicy: false,
  })
);

/* ------------------------------------------------------------------ */
/* CORS                                                                */
/*                                                                     */
/* The frontend is served by this same Express app, so same-origin     */
/* requests need no CORS at all. ALLOWED_ORIGINS exists only for the   */
/* case where the frontend is hosted separately. Credentials are on,   */
/* so a wildcard origin is deliberately NOT permitted.                 */
/* ------------------------------------------------------------------ */
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

if (allowedOrigins.length) {
  app.use(
    cors({
      origin(origin, cb) {
        if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
        return cb(new Error("Origin not allowed by CORS"));
      },
      credentials: true,
    })
  );
}

/* ------------------------------------------------------------------ */
/* Parsers                                                             */
/* ------------------------------------------------------------------ */
app.use(express.json({ limit: "16kb" })); // small cap — these are tiny JSON bodies
app.use(cookieParser());

/* ------------------------------------------------------------------ */
/* API routes                                                          */
/* ------------------------------------------------------------------ */
app.get("/api/health", (req, res) => res.json({ ok: true, time: new Date().toISOString() }));
app.use("/api", registerRoutes);
app.use("/api", authRoutes);

// TEST-ONLY routes. Mounted only when ENABLE_TEST_OTP_API=true, a
// TEST_OTP_TOKEN of 16+ chars is set, and SMS_MODE=mock. With the default
// configuration this router does not exist and /api/test/* 404s.
if (testing.ENABLED) {
  app.use("/api/test", require("./routes/testing"));
}

/* ------------------------------------------------------------------ */
/* Frontend                                                            */
/* ------------------------------------------------------------------ */
app.use(express.static(path.join(__dirname, "..", "public")));

app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "index.html"));
});

/* ------------------------------------------------------------------ */
/* Error handler                                                       */
/*                                                                     */
/* Logs the real error server-side, returns a generic message to the   */
/* client. Stack traces and SQL text must never reach the browser.     */
/* ------------------------------------------------------------------ */
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(`[error] ${req.method} ${req.path}:`, err.message);
  if (process.env.NODE_ENV !== "production") console.error(err.stack);

  if (res.headersSent) return;
  res.status(500).json({
    error: "server_error",
    message: "Something went wrong. Please try again.",
  });
});

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\nSecureID server running → http://localhost:${PORT}`);
    console.log(`  database : ${process.env.DATABASE_URL ? "configured" : "MISSING DATABASE_URL"}`);
    console.log(`  email    : ${describeEmailConfig()}`);
    console.log(`  sms      : ${describeSmsConfig()}`);
    console.log(`  test API : ${testing.describeTestConfig()}\n`);
  });
}

module.exports = app;
