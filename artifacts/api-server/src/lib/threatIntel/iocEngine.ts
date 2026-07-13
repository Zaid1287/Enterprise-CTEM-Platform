/**
 * IOC Intelligence Engine
 * Normalises raw threat feed records into a common schema,
 * deduplicates via upsert on (type, value) — the canonical IOC identity key —
 * aggregates sources, and calculates a 0-100 threat score based on:
 *   source_reliability × confidence × severity × freshness × exploitation_factor
 */
import { eq, and, sql } from "drizzle-orm";
import { db, tiIocsTable } from "@workspace/db";
import { logger } from "../logger";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface NormalizedIoc {
  type: string;
  value: string;
  source: string;
  sourceUrl?: string;
  tlp?: string;
  confidence?: number;
  severity?: string;
  tags?: string[];
  malwareFamilies?: string[];
  threatActors?: string[];
  campaigns?: string[];
  country?: string;
  asn?: string;
  description?: string;
  /** Actual first-seen date from the feed (used for freshness scoring). */
  firstSeen?: Date;
  /** active | probable | possible | unknown */
  exploitationStatus?: string;
  expiresAt?: Date;
  rawData?: Record<string, unknown>;
}

// ── Scoring helpers ───────────────────────────────────────────────────────────

const SOURCE_RELIABILITY: Record<string, number> = {
  cisa_kev:       1.00,
  alienvault_otx: 0.90,
  malwarebazaar:  0.90,
  threatfox:      0.88,
  phishtank:      0.88,
  urlhaus:        0.85,
  abuseipdb:      0.80,
  greynoise:      0.80,
  nvd_cve:        0.95,
  manual:         0.70,
};

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 1.00,
  high:     0.80,
  medium:   0.55,
  low:      0.30,
  info:     0.10,
};

const EXPLOITATION_FACTOR: Record<string, number> = {
  active:   1.30,
  probable: 1.15,
  possible: 1.05,
  unknown:  1.00,
};

function freshnessScore(firstSeen: Date): number {
  const ageDays = (Date.now() - firstSeen.getTime()) / 86_400_000;
  if (ageDays <= 1)   return 1.00;
  if (ageDays <= 7)   return 0.90;
  if (ageDays <= 30)  return 0.75;
  if (ageDays <= 90)  return 0.50;
  if (ageDays <= 180) return 0.30;
  return 0.15;
}

export function calculateThreatScore(ioc: NormalizedIoc): number {
  const rel    = SOURCE_RELIABILITY[ioc.source] ?? 0.70;
  const conf   = (ioc.confidence ?? 50) / 100;
  const sev    = SEVERITY_WEIGHT[ioc.severity ?? "medium"] ?? 0.55;
  const fresh  = freshnessScore(ioc.firstSeen ?? new Date());
  const expFac = EXPLOITATION_FACTOR[ioc.exploitationStatus ?? "unknown"] ?? 1.00;
  return Math.min(100, Math.round(rel * conf * sev * fresh * expFac * 100));
}

// ── Upsert ────────────────────────────────────────────────────────────────────

export interface UpsertResult {
  added: number;
  updated: number;
  skipped: number;
}

const BATCH_SIZE = 200;

export async function upsertIocs(iocs: NormalizedIoc[]): Promise<UpsertResult> {
  if (iocs.length === 0) return { added: 0, updated: 0, skipped: 0 };

  let added = 0;

  for (let i = 0; i < iocs.length; i += BATCH_SIZE) {
    const batch = iocs.slice(i, i + BATCH_SIZE);
    const rows = batch.map(ioc => ({
      type:               ioc.type,
      value:              ioc.value,
      source:             ioc.source,
      sources:            [ioc.source],
      sourceUrl:          ioc.sourceUrl ?? null,
      tlp:                ioc.tlp ?? "white",
      confidence:         ioc.confidence ?? 50,
      severity:           ioc.severity ?? "medium",
      tags:               ioc.tags ?? [],
      malwareFamilies:    ioc.malwareFamilies ?? [],
      threatActors:       ioc.threatActors ?? [],
      campaigns:          ioc.campaigns ?? [],
      country:            ioc.country ?? null,
      asn:                ioc.asn ?? null,
      description:        ioc.description ?? null,
      threatScore:        calculateThreatScore(ioc),
      exploitationStatus: ioc.exploitationStatus ?? "unknown",
      firstSeen:          ioc.firstSeen ?? new Date(),
      expiresAt:          ioc.expiresAt ?? null,
      rawData:            ioc.rawData ?? null,
      lastSeen:           new Date(),
    }));

    try {
      const result = await db.insert(tiIocsTable)
        .values(rows)
        .onConflictDoUpdate({
          // Dedup on canonical (type, value) — same IOC from any source updates the record
          target: [tiIocsTable.type, tiIocsTable.value],
          set: {
            // Merge source into the sources array (deduplicated via DISTINCT)
            sources:            sql`(SELECT array(SELECT DISTINCT UNNEST(ti_iocs.sources || excluded.sources)))`,
            // Keep the highest confidence and threat score seen
            confidence:         sql`GREATEST(ti_iocs.confidence, excluded.confidence)`,
            threatScore:        sql`GREATEST(ti_iocs.threat_score, excluded.threat_score)`,
            // Union all enrichment arrays
            tags:               sql`(SELECT array(SELECT DISTINCT UNNEST(ti_iocs.tags || excluded.tags)))`,
            malwareFamilies:    sql`(SELECT array(SELECT DISTINCT UNNEST(ti_iocs.malware_families || excluded.malware_families)))`,
            threatActors:       sql`(SELECT array(SELECT DISTINCT UNNEST(ti_iocs.threat_actors || excluded.threat_actors)))`,
            campaigns:          sql`(SELECT array(SELECT DISTINCT UNNEST(ti_iocs.campaigns || excluded.campaigns)))`,
            // Escalate exploitation status if new source has higher confidence
            exploitationStatus: sql`CASE WHEN excluded.exploitation_status = 'active' THEN 'active'
              WHEN ti_iocs.exploitation_status = 'active' THEN 'active'
              WHEN excluded.exploitation_status = 'probable' THEN 'probable'
              WHEN ti_iocs.exploitation_status = 'probable' THEN 'probable'
              ELSE COALESCE(excluded.exploitation_status, ti_iocs.exploitation_status)
            END`,
            seenCount:          sql`ti_iocs.seen_count + 1`,
            lastSeen:           sql`NOW()`,
            isActive:           sql`true`,
            rawData:            sql`excluded.raw_data`,
          },
        })
        .returning({ id: tiIocsTable.id });

      added += result.length;
    } catch (err) {
      logger.warn({ err, batchSize: batch.length }, "IOC batch upsert error");
    }
  }

  return { added, updated: 0, skipped: 0 };
}

// ── On-demand IOC lookup ──────────────────────────────────────────────────────

export async function lookupIoc(value: string) {
  const rows = await db.select().from(tiIocsTable)
    .where(eq(tiIocsTable.value, value.toLowerCase().trim()))
    .limit(10);
  return rows;
}
