-- SecureID — PostgreSQL schema (Supabase free tier compatible)
--
-- Run this once against your Supabase database:
--   npm run db:migrate
-- ...or paste it into the Supabase dashboard SQL editor.
--
-- Everything is idempotent, so re-running it is safe.

create extension if not exists pgcrypto;

/* ------------------------------------------------------------------ */
/* users                                                               */
/* ------------------------------------------------------------------ */
create table if not exists users (
  id                    uuid primary key default gen_random_uuid(),
  full_name             text        not null,
  email                 text        not null unique,
  mobile                text        not null,
  -- bcrypt hash only. The plaintext password is never stored or logged.
  password_hash         text        not null,
  email_verified        boolean     not null default false,
  mobile_verified       boolean     not null default false,
  mfa_enabled           boolean     not null default false,
  mfa_method            text,
  -- base32 TOTP secret. Never returned by any API except once, at enrollment.
  totp_secret           text,
  totp_attempts         integer     not null default 0,
  registration_complete boolean     not null default false,
  created_at            timestamptz not null default now(),
  updated_at            timestamptz not null default now(),

  constraint users_mfa_method_check
    check (mfa_method is null or mfa_method in ('authenticator', 'sms', 'email'))
);

-- Temporary account lockout after repeated failed logins. Counted per
-- account (not per IP), so spreading an attack across many addresses does
-- not help. Reset on any successful password check.
alter table users add column if not exists failed_login_attempts integer not null default 0;
alter table users add column if not exists locked_until timestamptz;

create index if not exists users_email_idx on users (lower(email));

/* ------------------------------------------------------------------ */
/* otp_challenges                                                      */
/*                                                                     */
/* Every challenge is bound to a user AND a purpose AND a channel.     */
/* Verification must match all three — this is what stops someone      */
/* verifying their own OTP while passing another user's id, or         */
/* replaying an email challenge against the SMS endpoint.              */
/* ------------------------------------------------------------------ */
create table if not exists otp_challenges (
  id           uuid        primary key default gen_random_uuid(),
  user_id      uuid        not null references users (id) on delete cascade,
  purpose      text        not null,
  channel      text        not null,
  destination  text        not null,
  -- SHA-256 hash of the OTP. The plaintext code is never stored.
  otp_hash     text        not null,
  -- TEST ONLY. Populated exclusively when ENABLE_TEST_OTP_API=true, so an
  -- evaluator can read back a simulated SMS code. NULL in every normal
  -- deployment — the flag defaults to false and refuses to turn on when a
  -- real SMS provider is configured. See server/routes/testing.js.
  test_otp     text,
  expires_at   timestamptz not null,
  attempts     integer     not null default 0,
  max_attempts integer     not null default 3,
  consumed     boolean     not null default false,
  consumed_at  timestamptz,
  created_at   timestamptz not null default now(),

  constraint otp_challenges_channel_check
    check (channel in ('email', 'sms')),
  constraint otp_challenges_purpose_check
    check (purpose in ('register-email', 'register-sms', 'mfa-email', 'mfa-sms', 'login-mfa'))
);

-- Added after the first release; keeps `npm run db:migrate` safe to re-run
-- against a database created before the test API existed.
alter table otp_challenges add column if not exists test_otp text;

create index if not exists otp_challenges_user_purpose_idx
  on otp_challenges (user_id, purpose, channel);
create index if not exists otp_challenges_expires_idx
  on otp_challenges (expires_at);

/* ------------------------------------------------------------------ */
/* sessions                                                            */
/*                                                                     */
/* The JWT carries a jti that points at a row here. Logout marks the   */
/* row revoked, so a stolen-but-unexpired token stops working — which  */
/* a stateless-only JWT could not do.                                  */
/* ------------------------------------------------------------------ */
create table if not exists sessions (
  id         uuid        primary key default gen_random_uuid(),
  user_id    uuid        not null references users (id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  user_agent text,
  ip         text
);

create index if not exists sessions_user_idx on sessions (user_id);
create index if not exists sessions_expires_idx on sessions (expires_at);

/* ------------------------------------------------------------------ */
/* rate_limits                                                         */
/*                                                                     */
/* Fixed-window counters. Kept in the DB rather than in process memory */
/* because Vercel runs many isolated instances — an in-memory limiter  */
/* would reset on every cold start and be trivially bypassed.          */
/* ------------------------------------------------------------------ */
create table if not exists rate_limits (
  bucket_key   text        not null,
  window_start timestamptz not null,
  hits         integer     not null default 0,
  primary key (bucket_key, window_start)
);

create index if not exists rate_limits_window_idx on rate_limits (window_start);

/* ------------------------------------------------------------------ */
/* Housekeeping helper — safe to call periodically.                    */
/* ------------------------------------------------------------------ */
create or replace function purge_expired_secureid_rows() returns void as $$
begin
  delete from otp_challenges where expires_at < now() - interval '1 day';
  delete from sessions       where expires_at < now() - interval '7 days';
  delete from rate_limits    where window_start < now() - interval '1 day';
end;
$$ language plpgsql;
