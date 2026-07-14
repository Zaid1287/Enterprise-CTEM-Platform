/**
 * fix-brand-abuse-count.ts
 *
 * One-time idempotent migration that corrects historical `brand_threat_scans` rows
 * where `brand_abuse_count` was inflated by ad monitoring results (they were summed
 * together before `ad_monitoring_count` became its own separate column).
 *
 * Safe to re-run: uses ADD COLUMN IF NOT EXISTS and recomputes both counts from
 * child-table row counts (the ground truth), so repeated runs produce the same result.
 *
 * Run with:
 *   pnpm --filter @workspace/scripts run fix-brand-abuse-count
 *
 * Verification query (run after migration to confirm correctness):
 *
 *   SELECT id, domain, brand_abuse_count, ad_monitoring_count,
 *          (SELECT COUNT(*) FROM brand_abuse_results   WHERE scan_id = bts.id) AS actual_abuse,
 *          (SELECT COUNT(*) FROM ad_monitoring_results WHERE scan_id = bts.id) AS actual_ads
 *   FROM brand_threat_scans bts
 *   WHERE status = 'done'
 *   ORDER BY id;
 *
 * Expected: brand_abuse_count = actual_abuse AND ad_monitoring_count = actual_ads for all rows.
 */

import pg from "pg";

const { Pool } = pg;

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL environment variable is not set.");
  process.exit(1);
}

async function main() {
  const pool = new Pool({ connectionString: DATABASE_URL });
  const client = await pool.connect();

  try {
    console.log("=== fix-brand-abuse-count migration ===\n");

    // ── Step 1: Add ad_monitoring_count column if missing ─────────────────────
    console.log("Step 1: Ensuring ad_monitoring_count column exists...");
    await client.query(`
      ALTER TABLE brand_threat_scans
      ADD COLUMN IF NOT EXISTS ad_monitoring_count integer NOT NULL DEFAULT 0
    `);
    console.log("  ✓ Column present (created or already existed).\n");

    // ── Step 2: Recompute counts from child tables for all completed scans ────
    //
    // Corrects any historical rows where brand_abuse_count was stored as
    // (brand_abuse_results + ad_monitoring_results) before the columns were
    // separated.  Ground truth: actual row counts in each child table.
    //
    // Only touches rows with status = 'done' — pending/running/error scans
    // are left untouched so an in-flight scan is never corrupted mid-run.
    console.log("Step 2: Recomputing brand_abuse_count and ad_monitoring_count from child tables...");
    const result = await client.query<{
      id: number;
      domain: string;
      brand_abuse_count: string;
      ad_monitoring_count: string;
    }>(`
      UPDATE brand_threat_scans bts
      SET
        brand_abuse_count = (
          SELECT COUNT(*) FROM brand_abuse_results bar
          WHERE bar.scan_id = bts.id
        ),
        ad_monitoring_count = (
          SELECT COUNT(*) FROM ad_monitoring_results amr
          WHERE amr.scan_id = bts.id
        )
      WHERE bts.status = 'done'
      RETURNING id, domain, brand_abuse_count, ad_monitoring_count
    `);

    if (result.rows.length === 0) {
      console.log("  No completed scans found — nothing to update.\n");
    } else {
      console.log(`  Updated ${result.rows.length} completed scan row(s):\n`);
      for (const row of result.rows) {
        console.log(
          `    scan #${row.id} (${row.domain}): ` +
          `brand_abuse_count=${row.brand_abuse_count}, ad_monitoring_count=${row.ad_monitoring_count}`,
        );
      }
      console.log();
    }

    console.log("=== Migration complete ===");
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error("Migration failed:", err);
  process.exit(1);
});
