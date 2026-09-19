/**
 * PostgreSQL connection pool (Supabase free tier).
 *
 * Serverless note: Vercel may run many concurrent instances of this
 * process, and each one would otherwise open its own pool. Supabase's
 * free tier has a small direct-connection limit, so we:
 *   1. point DATABASE_URL at Supabase's **transaction pooler** (port 6543),
 *   2. cap this pool at a couple of connections,
 *   3. reuse the pool across warm invocations via globalThis.
 */

const { Pool } = require("pg");

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error(
    "DATABASE_URL is not set. Copy .env.example to .env and add your Supabase connection string."
  );
}

function createPool() {
  return new Pool({
    connectionString,
    // Supabase requires TLS. Its certificate chain is not in Node's default
    // trust store for the pooler host, hence rejectUnauthorized: false —
    // the connection is still encrypted.
    ssl: { rejectUnauthorized: false },
    max: Number(process.env.PG_POOL_MAX || 2),
    idleTimeoutMillis: 10_000,
    connectionTimeoutMillis: 10_000,
    // The transaction pooler does not support server-side prepared
    // statements; node-postgres only uses them for *named* queries, and
    // we never name ours, so parameterised queries work as normal.
  });
}

// Reuse across warm serverless invocations instead of leaking a new pool.
const pool = globalThis.__secureidPool || createPool();
if (!globalThis.__secureidPool) globalThis.__secureidPool = pool;

pool.on("error", (err) => {
  console.error("[db] idle client error:", err.message);
});

/** Run a parameterised query. Never interpolate user input into SQL. */
async function query(text, params) {
  return pool.query(text, params);
}

/** Convenience: first row or null. */
async function queryOne(text, params) {
  const { rows } = await pool.query(text, params);
  return rows[0] || null;
}

/** Run several statements inside a transaction. */
async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { pool, query, queryOne, withTransaction };
