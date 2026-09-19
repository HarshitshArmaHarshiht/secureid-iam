#!/usr/bin/env node
/**
 * Applies server/db/schema.sql to the database in DATABASE_URL.
 * Run with:  npm run db:migrate
 */

require("dotenv").config({ path: require("path").join(__dirname, "..", "..", ".env") });

const fs = require("fs");
const path = require("path");

async function main() {
  const { pool } = require("./pool");
  const sql = fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8");

  console.log("Applying schema to", maskUrl(process.env.DATABASE_URL), "...");
  await pool.query(sql);

  const { rows } = await pool.query(
    `select table_name from information_schema.tables
      where table_schema = 'public'
        and table_name in ('users','otp_challenges','sessions','rate_limits')
      order by table_name`
  );

  console.log("\nTables present:");
  rows.forEach((r) => console.log("  ✓", r.table_name));

  if (rows.length !== 4) {
    console.error("\nExpected 4 tables, found", rows.length);
    process.exitCode = 1;
  } else {
    console.log("\nSchema applied successfully.");
  }

  await pool.end();
}

function maskUrl(url = "") {
  return url.replace(/:\/\/([^:]+):([^@]+)@/, "://$1:****@");
}

main().catch((err) => {
  console.error("\nMigration failed:", err.message);
  process.exit(1);
});
