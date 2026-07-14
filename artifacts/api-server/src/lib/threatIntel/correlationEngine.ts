/**
 * Threat Intelligence Correlation Engine
 *
 * Correlates tenant findings against the global TI database:
 *  - IOC matching  (IP, domain, URL)
 *  - CVE intel linkage (actors, malware, exploitation status, KEV, EPSS)
 *  - C2 server IP matching
 *  - Threat-actor & malware name resolution from CVE links
 *
 * Called by:
 *  - beatScheduler after every TI feed refresh
 *  - POST /api/threat-intel/correlate  (on-demand, per tenant)
 */

import {
  db,
  findingsTable,
  assetsTable,
  tiIocsTable,
  tiThreatActorsTable,
  tiCampaignsTable,
  tiMalwareTable,
  tiC2ServersTable,
  tiCveIntelTable,
  tiAssetCorrelationsTable,
} from "@workspace/db";
import { eq, and, inArray, notInArray } from "drizzle-orm";
import { logger } from "../logger";

// ── Result types ─────────────────────────────────────────────────────────────

interface MatchedActor {
  id: number;
  name: string;
  country: string | null;
  motivation: string | null;
  riskScore: number;
  mitreId: string | null;
  matchReason: string;
}

interface MatchedCampaign {
  id: number;
  name: string;
  status: string;
  actorName: string | null;
  matchReason: string;
}

interface MatchedMalware {
  id: number;
  name: string;
  malwareType: string;
  riskScore: number;
  matchReason: string;
}

interface MatchedIoc {
  id: number;
  type: string;
  value: string;
  severity: string;
  threatScore: number;
  exploitationStatus: string;
  sources: string[];
  matchReason: string;
}

interface MatchedCve {
  cveId: string;
  cvss: number | null;
  epss: number | null;
  isKev: boolean;
  exploitationStatus: string;
  linkedActors: string[];
  linkedMalware: string[];
  patchAvailable: boolean;
  description: string | null;
}

// ── Correlation context (loaded once per tenant run) ─────────────────────────

interface CorrelationContext {
  iocMap: Map<string, any>;
  actorMap: Map<string, any>;
  actorIdMap: Map<number, any>;
  campaignsByActorId: Map<number, any[]>;
  malwareMap: Map<string, any>;
  c2IpSet: Set<string>;
  cveMap: Map<string, any>;
  assetMap: Map<number, any>;
}

async function buildCorrelationContext(
  tenantId: number,
  cveIds: string[],
): Promise<CorrelationContext> {
  const [iocs, actors, campaigns, malware, c2Servers, assets, cveRows] =
    await Promise.all([
      db.select().from(tiIocsTable).where(eq(tiIocsTable.isActive, true)).limit(20_000),
      db.select().from(tiThreatActorsTable),
      db.select().from(tiCampaignsTable),
      db.select().from(tiMalwareTable),
      db
        .select({ ip: tiC2ServersTable.ip })
        .from(tiC2ServersTable)
        .where(eq(tiC2ServersTable.isActive, true)),
      db.select().from(assetsTable).where(eq(assetsTable.tenantId, tenantId)),
      cveIds.length > 0
        ? db
            .select()
            .from(tiCveIntelTable)
            .where(inArray(tiCveIntelTable.cveId, cveIds.slice(0, 500)))
        : Promise.resolve([] as any[]),
    ]);

  // IOC lookup: type:value → row
  const iocMap = new Map<string, any>();
  for (const ioc of iocs) {
    iocMap.set(`${ioc.type}:${ioc.value.toLowerCase()}`, ioc);
  }

  // Actor lookup: name (and aliases) → row
  const actorMap = new Map<string, any>();
  const actorIdMap = new Map<number, any>();
  for (const a of actors) {
    actorMap.set(a.name.toLowerCase(), a);
    actorIdMap.set(a.id, a);
    for (const alias of (a.aliases ?? [])) {
      actorMap.set((alias as string).toLowerCase(), a);
    }
  }

  // Campaigns grouped by actorId
  const campaignsByActorId = new Map<number, any[]>();
  for (const c of campaigns) {
    if (c.actorId != null) {
      if (!campaignsByActorId.has(c.actorId)) campaignsByActorId.set(c.actorId, []);
      campaignsByActorId.get(c.actorId)!.push(c);
    }
  }

  // Malware lookup: name (and aliases) → row
  const malwareMap = new Map<string, any>();
  for (const m of malware) {
    malwareMap.set(m.name.toLowerCase(), m);
    for (const alias of (m.aliases ?? [])) {
      malwareMap.set((alias as string).toLowerCase(), m);
    }
  }

  const c2IpSet = new Set<string>(c2Servers.map((s) => s.ip));

  const cveMap = new Map<string, any>();
  for (const c of cveRows) cveMap.set(c.cveId, c);

  const assetMap = new Map<number, any>();
  for (const a of assets) assetMap.set(a.id, a);

  return {
    iocMap,
    actorMap,
    actorIdMap,
    campaignsByActorId,
    malwareMap,
    c2IpSet,
    cveMap,
    assetMap,
  };
}

// ── Per-finding correlator ────────────────────────────────────────────────────

function correlateFinding(finding: any, ctx: CorrelationContext): {
  matchedActors: MatchedActor[];
  matchedCampaigns: MatchedCampaign[];
  matchedMalware: MatchedMalware[];
  matchedIocs: MatchedIoc[];
  matchedCves: MatchedCve[];
  exploitationStatus: string;
  threatScore: number;
  riskBoost: number;
  correlationBasis: string[];
} {
  const asset = ctx.assetMap.get(finding.assetId);
  const matchedActors: MatchedActor[] = [];
  const matchedCampaigns: MatchedCampaign[] = [];
  const matchedMalware: MatchedMalware[] = [];
  const matchedIocs: MatchedIoc[] = [];
  const matchedCves: MatchedCve[] = [];
  const correlationBasis: string[] = [];
  const seenActorIds = new Set<number>();
  const seenMalwareIds = new Set<number>();
  const seenIocIds = new Set<number>();

  let score = 0;
  let cveIntel: any = null;

  // ── 1. CVE intelligence ────────────────────────────────────────────────────
  if (finding.cve) {
    cveIntel = ctx.cveMap.get(finding.cve);
    if (cveIntel) {
      score += 10;
      correlationBasis.push("cve_intel_match");

      matchedCves.push({
        cveId: cveIntel.cveId,
        cvss: cveIntel.cvss,
        epss: cveIntel.epss,
        isKev: cveIntel.isKev,
        exploitationStatus: cveIntel.exploitationStatus,
        linkedActors: cveIntel.linkedActors ?? [],
        linkedMalware: cveIntel.linkedMalware ?? [],
        patchAvailable: cveIntel.patchAvailable,
        description: cveIntel.description,
      });

      if (cveIntel.isKev) { score += 30; correlationBasis.push("cve_kev"); }
      if (cveIntel.exploitationStatus === "active") { score += 25; correlationBasis.push("cve_active_exploitation"); }
      if (cveIntel.pocPublic) { score += 10; correlationBasis.push("poc_public"); }
      if (cveIntel.epss && cveIntel.epss > 0.5) { score += 15; correlationBasis.push("high_epss"); }

      // Resolve actors from CVE links
      let actorBonus = 0;
      for (const actorName of (cveIntel.linkedActors ?? [])) {
        const actor = ctx.actorMap.get((actorName as string).toLowerCase());
        if (actor && !seenActorIds.has(actor.id) && actorBonus < 30) {
          seenActorIds.add(actor.id);
          matchedActors.push({
            id: actor.id,
            name: actor.name,
            country: actor.country,
            motivation: actor.motivation,
            riskScore: actor.riskScore,
            mitreId: actor.mitreId,
            matchReason: `linked to ${finding.cve}`,
          });
          actorBonus += 15;
          score += 15;
          correlationBasis.push("actor_via_cve");
          // Campaigns for this actor
          for (const c of (ctx.campaignsByActorId.get(actor.id) ?? []).slice(0, 3)) {
            matchedCampaigns.push({
              id: c.id, name: c.name, status: c.status,
              actorName: actor.name, matchReason: `campaign by ${actor.name}`,
            });
          }
        }
      }

      // Resolve malware from CVE links
      for (const malwareName of (cveIntel.linkedMalware ?? [])) {
        const m = ctx.malwareMap.get((malwareName as string).toLowerCase());
        if (m && !seenMalwareIds.has(m.id)) {
          seenMalwareIds.add(m.id);
          matchedMalware.push({
            id: m.id, name: m.name, malwareType: m.malwareType,
            riskScore: m.riskScore, matchReason: `linked to ${finding.cve}`,
          });
          score += 8;
          correlationBasis.push("malware_via_cve");
        }
      }
    }
  }

  // ── 2. Asset IOC matching ──────────────────────────────────────────────────
  if (asset) {
    const ipAddr: string | null =
      asset.ipAddress ?? (asset.type === "ip" ? asset.value : null);

    const checks: Array<{ type: string; val: string }> = [];

    if (ipAddr) checks.push({ type: "ip", val: ipAddr.toLowerCase() });

    if (asset.type === "domain" || asset.type === "subdomain") {
      checks.push({ type: "domain", val: asset.value.toLowerCase() });
    } else if (
      asset.value &&
      !asset.value.startsWith("http") &&
      asset.value.includes(".")
    ) {
      checks.push({ type: "domain", val: asset.value.toLowerCase() });
    }

    if (asset.type === "url") {
      checks.push({ type: "url", val: asset.value.toLowerCase() });
    }

    for (const { type, val } of checks) {
      const ioc = ctx.iocMap.get(`${type}:${val}`);
      if (ioc && !seenIocIds.has(ioc.id)) {
        seenIocIds.add(ioc.id);
        matchedIocs.push({
          id: ioc.id, type: ioc.type, value: ioc.value,
          severity: ioc.severity,
          threatScore: ioc.threatScore,
          exploitationStatus: ioc.exploitationStatus,
          sources: (ioc.sources as string[])?.length ? ioc.sources : [ioc.source],
          matchReason: `${type} match on asset value`,
        });
        const boost = type === "ip" ? 35 : type === "domain" ? 25 : 20;
        score += boost;
        correlationBasis.push(`ioc_${type}_match`);
      }
    }

    // ── 3. C2 server match ───────────────────────────────────────────────────
    if (ipAddr && ctx.c2IpSet.has(ipAddr)) {
      score += 40;
      correlationBasis.push("c2_match");
      if (!seenIocIds.size) {
        matchedIocs.push({
          id: -1, type: "ip", value: ipAddr,
          severity: "critical", threatScore: 90,
          exploitationStatus: "active",
          sources: ["feodo_tracker", "abuseipdb"],
          matchReason: "known C2 server IP",
        });
      }
    }
  }

  // ── 4. Severity base ──────────────────────────────────────────────────────
  const sevBase: Record<string, number> = { critical: 10, high: 7, medium: 4, low: 2, info: 0 };
  score += sevBase[finding.severity] ?? 0;

  score = Math.min(Math.round(score), 100);

  // ── 5. Exploitation status ─────────────────────────────────────────────────
  let exploitationStatus = "unknown";
  if (correlationBasis.includes("c2_match") || finding.isKev) {
    exploitationStatus = "active";
  } else if (cveIntel?.exploitationStatus === "active") {
    exploitationStatus = "active";
  } else if (cveIntel?.isKev) {
    exploitationStatus = "confirmed";
  } else if (matchedIocs.length > 0 || correlationBasis.some((b) => b.startsWith("ioc_"))) {
    exploitationStatus = "potential";
  } else if (cveIntel?.pocPublic || cveIntel) {
    exploitationStatus = "potential";
  }

  const riskBoost = Math.round(score * 0.3); // max 30

  return {
    matchedActors,
    matchedCampaigns,
    matchedMalware,
    matchedIocs,
    matchedCves,
    exploitationStatus,
    threatScore: score,
    riskBoost,
    correlationBasis,
  };
}

// ── Public entry point ────────────────────────────────────────────────────────

export async function runThreatIntelCorrelation(
  tenantId: number,
): Promise<{ correlated: number; updated: number; skipped: number }> {
  const startTs = Date.now();
  logger.info({ tenantId }, "TI correlation: starting");

  try {
    // Load findings — skip FP and auto-mitigated
    const findings = await db
      .select()
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, tenantId),
          notInArray(findingsTable.status, ["false_positive", "auto_mitigated"]),
        ),
      );

    if (findings.length === 0) {
      logger.info({ tenantId }, "TI correlation: no findings to correlate");
      return { correlated: 0, updated: 0, skipped: 0 };
    }

    // Extract unique CVE IDs
    const cveIds = [
      ...new Set(findings.filter((f) => f.cve).map((f) => f.cve!)),
    ];

    // Build in-memory context
    const ctx = await buildCorrelationContext(tenantId, cveIds);

    const toUpsert: any[] = [];
    let skipped = 0;

    for (const finding of findings) {
      const result = correlateFinding(finding, ctx);
      const hasMatches =
        result.matchedActors.length > 0 ||
        result.matchedIocs.length > 0 ||
        result.matchedCves.length > 0 ||
        result.matchedMalware.length > 0;

      if (!hasMatches) {
        skipped++;
        continue;
      }

      toUpsert.push({
        tenantId,
        findingId: finding.id,
        assetId: finding.assetId,
        matchedActors: result.matchedActors,
        matchedCampaigns: result.matchedCampaigns,
        matchedMalware: result.matchedMalware,
        matchedIocs: result.matchedIocs,
        matchedCves: result.matchedCves,
        exploitationStatus: result.exploitationStatus,
        threatScore: result.threatScore,
        riskBoost: result.riskBoost,
        correlationBasis: result.correlationBasis,
        correlatedAt: new Date(),
      });
    }

    // Delete + re-insert only for findings that have fresh TI matches this run.
    // This preserves manually-added correlation rows for findings the engine did not match.
    const upsertIds = toUpsert.map((r) => r.findingId);
    if (upsertIds.length > 0) {
      for (let i = 0; i < upsertIds.length; i += 500) {
        await db.delete(tiAssetCorrelationsTable).where(
          and(
            eq(tiAssetCorrelationsTable.tenantId, tenantId),
            inArray(tiAssetCorrelationsTable.findingId, upsertIds.slice(i, i + 500)),
          ),
        );
      }
      for (let i = 0; i < toUpsert.length; i += 100) {
        await db.insert(tiAssetCorrelationsTable).values(toUpsert.slice(i, i + 100));
      }
    }

    const durationMs = Date.now() - startTs;
    logger.info(
      { tenantId, correlated: toUpsert.length, skipped, durationMs },
      "TI correlation: completed",
    );
    return { correlated: toUpsert.length, updated: toUpsert.length, skipped };
  } catch (err) {
    logger.error({ err, tenantId }, "TI correlation: failed");
    throw err;
  }
}
