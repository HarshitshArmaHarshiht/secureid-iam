# SecureID — IAM Registration & Login Journey

An IAM-style identity system built with Node/Express and vanilla
HTML/CSS/JS, backed by PostgreSQL.

```
Registration → Email OTP → SMS OTP → MFA setup → Success → Login → /api/me
```

Everything runs on free tiers: **Vercel** (hosting), **Supabase**
(PostgreSQL), **Gmail SMTP** (email). No paid service is required.

---

## Quick start

```bash
npm install
cp .env.example .env     # then fill in the values (see below)
npm run db:migrate       # creates the tables in your Supabase database
npm start
```

Open http://localhost:3000.

---

## Environment variables

Copy `.env.example` to `.env`. **Never commit `.env`** — it is gitignored.

### 1. `DATABASE_URL` — Supabase (free)

Supabase dashboard → **Project Settings → Database → Connection string**.

- Local development: the direct connection (port **5432**) is fine.
- Vercel: use the **connection pooling** string (port **6543**). Serverless
  functions open many short-lived connections and will exhaust the free
  tier's direct-connection limit otherwise.

If your password contains `@ : / ? # &` you **must** URL-encode it —
`@` becomes `%40` — or the connection string parses wrongly.

### 2. `JWT_SECRET`

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

Minimum 32 characters. The app refuses to start without it.

### 3. Email — Gmail SMTP (free)

Use a **dedicated** Gmail account, not your personal one.

1. Turn on **2-Step Verification** for that account.
2. Google Account → Security → **App passwords** → generate one.
3. You get 16 characters in 4 groups (`abcd efgh ijkl mnop`). Spaces are
   optional; the total must be exactly 16 letters.
4. Put it in `EMAIL_PASSWORD`. **Never use the account's real password.**

```
EMAIL_MODE=smtp
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-address@gmail.com
EMAIL_PASSWORD=abcdefghijklmnop
```

Set `EMAIL_MODE=mock` to print codes to the server console instead of
sending them — useful offline and in tests.

### 4. SMS — simulated

```
SMS_MODE=mock
OTP_DEV_ECHO=false
```

**SMS is simulated. No message is sent.** Real delivery to an Indian
(+91) number requires a paid, KYC-verified, DLT-registered gateway —
Twilio, MSG91 and Fast2SMS all charge for this and none offers a usable
free tier. Rather than pretend otherwise, the transport is stubbed while
everything security-relevant stays real:

| Property | Mock SMS | Real SMS |
|---|---|---|
| CSPRNG-generated code | yes | yes |
| Stored only as a SHA-256 hash | yes | yes |
| 2:45 expiry | yes | yes |
| 3-attempt cap | yes | yes |
| Single-use | yes | yes |
| Rate-limited | yes | yes |
| Actually leaves the server | **no** | yes |

In mock mode the code is printed to the **server console**:

```
[SMS:mock] to=9876543210  OTP=482913  (expires in 165s)
```

**`OTP_DEV_ECHO=true`** additionally returns the code in the API response
and shows it in a yellow "development mode" banner in the UI. That makes
a *deployed* demo completable, since Vercel's console isn't visible to a
visitor. It is off by default, is ignored when a real provider is
configured, and must stay off for anything holding real accounts.

To plug in a real gateway later, no code change is needed:

```
SMS_MODE=http
SMS_HTTP_URL=https://your-provider/send
SMS_HTTP_BODY={"to":"{{to}}","message":"{{message}}"}
SMS_HTTP_AUTH_HEADER=Authorization
SMS_HTTP_AUTH_VALUE=Bearer xxx
```

---

## API

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/register` | Create account, send email OTP |
| POST | `/api/send-email-otp` | Resend email OTP |
| POST | `/api/verify-email-otp` | Verify email OTP |
| POST | `/api/send-sms-otp` | Send mobile OTP |
| POST | `/api/verify-sms-otp` | Verify mobile OTP |
| POST | `/api/mfa/setup` | MFA **enrollment** (TOTP secret + QR, or a code) |
| POST | `/api/mfa/verify` | MFA **proof**, completes registration |
| GET | `/api/registration-status` | Caller's own signup progress |
| POST | `/api/login` | Password check → MFA challenge |
| POST | `/api/login/mfa` | MFA proof → session |
| GET | `/api/me` | Current user from the validated session |
| POST | `/api/logout` | Revoke the session |
| GET | `/api/health` | Liveness |

---

## Security design

### Passwords
bcryptjs, cost 10. Only the hash is stored. `/api/me` never returns it.
Unknown-email logins still run a bcrypt comparison so response timing
cannot be used to discover which addresses are registered.

### OTPs
Generated with `crypto.randomInt` (a CSPRNG — `Math.random` is
predictable from a few observed codes and is never used). Only a SHA-256
hash is stored; comparison is constant-time via `timingSafeEqual`. Codes
expire in 2:45, allow 3 attempts, and are consumed on first success.

### Challenge binding — the important one
Every challenge row carries `user_id`, `purpose` and `channel`, and
verification looks up **all of them together**:

```sql
select * from otp_challenges
 where id = $1 and user_id = $2 and purpose = $3 and channel = $4
 for update
```

After `POST /api/register` the server sets a signed **HttpOnly
`reg_session` cookie** and reads the user id from that on every later
step. A `userId` in the request body is ignored entirely. This closes a
real hole in the earlier version, where you could verify your own OTP
while passing someone else's id and mark *their* email verified.

`FOR UPDATE` locks the row, so two concurrent submissions cannot both
consume one challenge or both slip past the attempt counter.

### Rate limiting
Counters live in the `rate_limits` table, not in process memory.
`express-rate-limit`'s default store would reset on every Vercel cold
start and be trivially bypassed. Limits: 10 registrations per IP / 15min,
5 OTP sends per user / 15min, 20 verifies per user / 15min, 8 logins per
account / 15min. Creating a new challenge also invalidates the previous
unconsumed one, so resending cannot farm fresh attempt windows.

### Sessions
Login is two steps: a correct password returns a short-lived
`pendingToken`, **not** a session. Only `/api/login/mfa` issues the `sid`
cookie. That cookie is HttpOnly (page JavaScript, and therefore any XSS
payload, cannot read it), `SameSite=Lax`, and `Secure` in production.

The JWT carries a `jti` matching a row in `sessions`. `/api/me` validates
the signature, the expiry **and** that the row is unrevoked — so logout
genuinely invalidates a token that hasn't expired yet. A pure stateless
JWT could not do that.

### Other
Helmet with a restrictive CSP; CORS off by default (same-origin app) and
never wildcard-with-credentials; 16 KB JSON body cap; errors logged
server-side with only a generic message returned.

---

## Password strength

Implemented twice, deliberately: `public/js/password-strength.js` for
live feedback and `server/lib/validate.js` for the decision. Client-side
checks are a convenience, never a control — anyone can call the API
directly, which is why the server re-runs them.

Four hard rules (8+ chars, uppercase, number, symbol) plus a 0–6 score:

| Points | |
|---|---|
| +1 | 8+ characters |
| +1 | 12+ characters |
| +1 | lowercase letter |
| +1 | uppercase letter |
| +1 | digit |
| +1 | symbol |
| −2 | 3 identical in a row (`aaa`) |
| −2 | 4+ sequential (`abcd`, `1234`) |
| −2 | common base word — also **capped at Weak** |

`0–2 Weak · 3–4 Medium · 5–6 Strong`. Registration needs Medium.
`Passw0rd!` passes all four rules and is still rejected, because a common
base word is always Weak however much is bolted onto it.

No library — the whole rule set fits on one screen.

---

## Database schema

| Table | Holds |
|---|---|
| `users` | account, bcrypt hash, verification flags, TOTP secret |
| `otp_challenges` | hash, purpose, channel, expiry, attempts, consumed |
| `sessions` | login sessions; `revoked_at` makes logout real |
| `rate_limits` | fixed-window counters shared across instances |

Re-running `npm run db:migrate` is safe — the schema is idempotent.

---

## Deploying to Vercel

```bash
npm install -g vercel
vercel login
vercel --prod
```

Then in the Vercel dashboard → **Settings → Environment Variables**, add
every variable from `.env` — `DATABASE_URL` (pooling string, port 6543),
`JWT_SECRET`, the `EMAIL_*` values, `SMS_MODE=mock`, and
`NODE_ENV=production` so cookies are marked `Secure`. Redeploy after
adding them.

`vercel.json` routes every request to `api/index.js`, which wraps the same
Express app used locally, so one codebase serves both.

Name the project `<your-name>-secureid` to match the assignment's
`your-name-secureid.vercel.app` convention.

---

## Project structure

```
secureid/
├── api/index.js              # Vercel serverless entry
├── server/
│   ├── index.js              # Express app (helmet, CORS, routes)
│   ├── db/
│   │   ├── pool.js           # pg pool, serverless-safe
│   │   ├── schema.sql        # tables
│   │   └── migrate.js        # npm run db:migrate
│   ├── routes/
│   │   ├── register.js       # registration journey
│   │   └── auth.js           # login / logout / me
│   └── lib/
│       ├── users.js          # user repository
│       ├── challenge.js      # OTP lifecycle (user+purpose+channel bound)
│       ├── otp.js            # CSPRNG generation, hashing
│       ├── mailer.js         # SMTP / Resend / mock
│       ├── sms.js            # mock / http provider
│       ├── mfa.js            # RFC-6238 TOTP + QR
│       ├── auth.js           # JWT cookies, sessions, middleware
│       ├── ratelimit.js      # DB-backed limiter
│       └── validate.js       # input rules + strength scoring
├── public/
│   ├── index.html            # registration screens
│   ├── login.html            # login journey
│   ├── css/style.css
│   └── js/
│       ├── app.js            # registration state machine
│       ├── login.js          # login state machine
│       └── password-strength.js
├── .env.example
└── vercel.json
```

---

## Known limitations

- **SMS is simulated.** See above. The architecture is production-ready;
  only a paid gateway is missing.
- **Supabase free tier pauses** after ~7 days of inactivity. Open the
  dashboard to resume it, or the app will fail to connect.
- **Rate limit counters are approximate** at window boundaries — a fixed
  window lets up to 2× the limit through across a boundary. A sliding
  window would fix it; not worth the complexity here.
