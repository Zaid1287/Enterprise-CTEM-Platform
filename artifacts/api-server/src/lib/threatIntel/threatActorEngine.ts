/**
 * Threat Actor Engine — MITRE ATT&CK
 * Fetches the MITRE ATT&CK Enterprise STIX bundle from GitHub and upserts:
 *   • Intrusion sets  → ti_threat_actors
 *   • Campaigns       → ti_campaigns
 *   • Malware/tools   → ti_malware
 *   • Attack patterns → ti_actor_ttps (linked to actors via relationships)
 */
import { sql, eq } from "drizzle-orm";
import {
  db,
  tiThreatActorsTable,
  tiCampaignsTable,
  tiMalwareTable,
  tiActorTtpsTable,
} from "@workspace/db";
import { logger } from "../logger";

const ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";
const UA = "Sentinelware-CTEM-TI/1.0";

// ── STIX helpers ──────────────────────────────────────────────────────────────

function stixVal(obj: any, key: string): string {
  return String(obj?.[key] ?? "").trim();
}

function stixArr(obj: any, key: string): string[] {
  const v = obj?.[key];
  if (!Array.isArray(v)) return [];
  return v.filter(Boolean).map(String);
}

function stixAliases(obj: any): string[] {
  return [
    ...stixArr(obj, "aliases"),
    ...stixArr(obj, "x_mitre_aliases"),
    ...stixArr(obj, "associated_groups"),
  ].filter(a => a && a !== obj.name).slice(0, 20);
}

function extractCountry(obj: any): string | null {
  // MITRE ATT&CK doesn't have a country field; infer from known name→country mapping
  const name: string = (obj.name ?? "").toLowerCase();
  const map: Record<string, string> = {
    "apt28": "Russia", "apt29": "Russia", "sandworm": "Russia", "turla": "Russia",
    "cozy bear": "Russia", "fancy bear": "Russia",
    "lazarus group": "North Korea", "kimsuky": "North Korea", "andariel": "North Korea",
    "apt41": "China", "apt1": "China", "apt10": "China", "mustang panda": "China",
    "charming kitten": "Iran", "apt33": "Iran", "apt34": "Iran",
    "darkside": "Unknown", "revil": "Unknown", "conti": "Unknown",
  };
  for (const [k, v] of Object.entries(map)) {
    if (name.includes(k)) return v;
  }
  return null;
}

function extractMotivation(obj: any): string {
  const primary = stixArr(obj, "primary_motivation");
  const secondary = stixArr(obj, "secondary_motivations");
  const all = [...primary, ...secondary];
  if (all.length === 0) return "unknown";
  return all[0]!.toLowerCase().replace(/-/g, "_");
}

function extractTargetIndustries(obj: any): string[] {
  return stixArr(obj, "x_mitre_sectors").slice(0, 10);
}

function extractMitreId(obj: any): string | null {
  const refs: any[] = obj?.external_references ?? [];
  const mitre = refs.find((r: any) => r.source_name === "mitre-attack");
  return mitre?.external_id ?? null;
}

function extractMitreUrl(obj: any): string | null {
  const refs: any[] = obj?.external_references ?? [];
  const mitre = refs.find((r: any) => r.source_name === "mitre-attack");
  return mitre?.url ?? null;
}

function extractReferenceUrls(obj: any): string[] {
  const refs: any[] = obj?.external_references ?? [];
  return refs.map((r: any) => r.url as string).filter(Boolean).slice(0, 10);
}

function calcRiskScore(obj: any): number {
  // Use sophistication level and activity as rough proxy
  const soph = stixVal(obj, "sophistication");
  const sophScore: Record<string, number> = {
    "advanced": 90, "expert": 85, "innovator": 80,
    "intermediate": 60, "practitioner": 50, "minimal": 30,
  };
  return sophScore[soph.toLowerCase()] ?? 60;
}

// ── Tactic mapping from kill chain phase name ─────────────────────────────────

const TACTIC_MAP: Record<string, string> = {
  "initial-access": "Initial Access",
  "execution": "Execution",
  "persistence": "Persistence",
  "privilege-escalation": "Privilege Escalation",
  "defense-evasion": "Defense Evasion",
  "credential-access": "Credential Access",
  "discovery": "Discovery",
  "lateral-movement": "Lateral Movement",
  "collection": "Collection",
  "command-and-control": "Command and Control",
  "exfiltration": "Exfiltration",
  "impact": "Impact",
  "resource-development": "Resource Development",
  "reconnaissance": "Reconnaissance",
};

// ── Main ingest ───────────────────────────────────────────────────────────────

export interface MitreAttackResult {
  actors: number;
  campaigns: number;
  malware: number;
  ttps: number;
}

export async function runMitreAttackIngest(): Promise<MitreAttackResult> {
  logger.info("MITRE ATT&CK ingest: fetching enterprise bundle...");

  let bundle: any;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 120_000); // large file, 2min timeout
    const res = await fetch(ATTACK_URL, { headers: { "User-Agent": UA }, signal: ctrl.signal });
    clearTimeout(t);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    bundle = await res.json();
  } catch (err) {
    logger.warn({ err }, "MITRE ATT&CK fetch failed");
    return { actors: 0, campaigns: 0, malware: 0, ttps: 0 };
  }

  const objects: any[] = bundle?.objects ?? [];
  logger.info({ total: objects.length }, "MITRE ATT&CK bundle loaded");

  // Index by STIX id for relationship resolution
  const byId = new Map<string, any>();
  for (const obj of objects) {
    if (obj?.id) byId.set(obj.id, obj);
  }

  // Partition by type
  const intrusionSets = objects.filter(o => o.type === "intrusion-set" && !o.revoked);
  const campaigns = objects.filter(o => o.type === "campaign" && !o.revoked);
  const malwareObjs = objects.filter(o => (o.type === "malware" || o.type === "tool") && !o.revoked);
  const attackPatterns = objects.filter(o => o.type === "attack-pattern" && !o.revoked);
  const relationships = objects.filter(o => o.type === "relationship");

  // Build relationship index: sourceId → [{rel_type, targetId}]
  const relBySrc = new Map<string, Array<{ type: string; target: string }>>();
  for (const rel of relationships) {
    const src: string = rel.source_ref;
    const tgt: string = rel.target_ref;
    if (!relBySrc.has(src)) relBySrc.set(src, []);
    relBySrc.get(src)!.push({ type: rel.relationship_type, target: tgt });
  }

  // ── 1. Upsert threat actors (intrusion sets) ──────────────────────────────

  let actorsInserted = 0;
  const ACTOR_BATCH = 50;
  const stixIdToDbId = new Map<string, number>(); // stix_id → db id

  for (let i = 0; i < intrusionSets.length; i += ACTOR_BATCH) {
    const batch = intrusionSets.slice(i, i + ACTOR_BATCH);
    const rows = batch.map(obj => ({
      name:             obj.name as string,
      aliases:          stixAliases(obj),
      country:          extractCountry(obj),
      motivation:       extractMotivation(obj),
      targetIndustries: extractTargetIndustries(obj),
      targetCountries:  stixArr(obj, "x_mitre_target_countries"),
      description:      stixVal(obj, "description") || null,
      overview:         stixVal(obj, "x_mitre_overview") || null,
      firstSeen:        stixVal(obj, "first_seen") || null,
      lastSeen:         stixVal(obj, "last_seen") || null,
      sophistication:   stixVal(obj, "sophistication") || null,
      resourceLevel:    stixVal(obj, "resource_level") || null,
      isActive:         true,
      riskScore:        calcRiskScore(obj),
      confidenceScore:  70,
      mitreId:          extractMitreId(obj),
      mitreUrl:         extractMitreUrl(obj),
      referenceUrls:    extractReferenceUrls(obj),
      source:           "mitre_attack",
      updatedAt:        new Date(),
    }));

    try {
      const inserted = await db.insert(tiThreatActorsTable)
        .values(rows)
        .onConflictDoUpdate({
          target: tiThreatActorsTable.name,
          set: {
            aliases:          sql`excluded.aliases`,
            description:      sql`excluded.description`,
            mitreId:          sql`excluded.mitre_id`,
            mitreUrl:         sql`excluded.mitre_url`,
            riskScore:        sql`GREATEST(ti_threat_actors.risk_score, excluded.risk_score)`,
            isActive:         sql`true`,
            updatedAt:        sql`NOW()`,
            referenceUrls:    sql`excluded.reference_urls`,
          },
        })
        .returning({ id: tiThreatActorsTable.id, name: tiThreatActorsTable.name });

      // Map stix id → db id
      for (let j = 0; j < batch.length; j++) {
        const dbRow = inserted.find(r => r.name === batch[j].name);
        if (dbRow) stixIdToDbId.set(batch[j].id, dbRow.id);
      }
      actorsInserted += inserted.length;
    } catch (err) {
      logger.warn({ err }, "ATT&CK actor batch upsert error");
    }
  }

  // ── 2. Upsert campaigns ───────────────────────────────────────────────────

  let campaignsInserted = 0;
  const CAMP_BATCH = 100;

  for (let i = 0; i < campaigns.length; i += CAMP_BATCH) {
    const batch = campaigns.slice(i, i + CAMP_BATCH);
    const rows = batch.map(obj => {
      // Find the actor this campaign is attributed to via "attributed-to" relationship
      const rels = relBySrc.get(obj.id) ?? [];
      const attribution = rels.find(r => r.type === "attributed-to");
      const actorStixId = attribution?.target;
      const actorDbId = actorStixId ? stixIdToDbId.get(actorStixId) : null;
      const actorObj = actorStixId ? byId.get(actorStixId) : null;

      return {
        name:             obj.name as string,
        aliases:          stixArr(obj, "aliases"),
        description:      stixVal(obj, "description") || null,
        actorId:          actorDbId ?? null,
        actorName:        actorObj?.name ?? null,
        status:           "historical",
        targetIndustries: extractTargetIndustries(obj),
        targetCountries:  stixArr(obj, "x_mitre_target_countries"),
        startDate:        obj.first_seen ? String(obj.first_seen).slice(0, 10) : null,
        endDate:          obj.last_seen ? String(obj.last_seen).slice(0, 10) : null,
        mitreId:          extractMitreId(obj),
        objectives:       stixVal(obj, "objective") || null,
        source:           "mitre_attack",
        rawData:          { id: obj.id },
        updatedAt:        new Date(),
      };
    });

    try {
      const inserted = await db.insert(tiCampaignsTable)
        .values(rows)
        .onConflictDoUpdate({
          target: tiCampaignsTable.name,
          set: {
            description:      sql`excluded.description`,
            actorId:          sql`COALESCE(excluded.actor_id, ti_campaigns.actor_id)`,
            actorName:        sql`COALESCE(excluded.actor_name, ti_campaigns.actor_name)`,
            mitreId:          sql`excluded.mitre_id`,
            updatedAt:        sql`NOW()`,
          },
        })
        .returning({ id: tiCampaignsTable.id });
      campaignsInserted += inserted.length;
    } catch (err) {
      logger.warn({ err }, "ATT&CK campaign batch upsert error");
    }
  }

  // ── 3. Upsert malware / tools ─────────────────────────────────────────────

  let malwareInserted = 0;
  const MAL_BATCH = 100;

  for (let i = 0; i < malwareObjs.length; i += MAL_BATCH) {
    const batch = malwareObjs.slice(i, i + MAL_BATCH);
    const rows = batch.map(obj => {
      // Find associated actors via reverse relationships (actors use malware)
      const actorNames: string[] = [];
      for (const [srcId, rels] of relBySrc.entries()) {
        for (const rel of rels) {
          if (rel.type === "uses" && rel.target === obj.id) {
            const src = byId.get(srcId);
            if (src?.type === "intrusion-set") actorNames.push(src.name as string);
          }
        }
      }

      return {
        name:             obj.name as string,
        aliases:          stixAliases(obj),
        malwareType:      obj.type === "tool" ? "tool" : (stixArr(obj, "malware_types")[0] ?? "malware"),
        description:      stixVal(obj, "description") || null,
        platforms:        stixArr(obj, "x_mitre_platforms"),
        targetIndustries: extractTargetIndustries(obj),
        actorNames:       actorNames.slice(0, 10),
        capabilities:     stixArr(obj, "capabilities"),
        mitreId:          extractMitreId(obj),
        mitreUrl:         extractMitreUrl(obj),
        riskScore:        actorNames.length > 0 ? 70 : 50,
        source:           "mitre_attack",
        rawData:          { id: obj.id, type: obj.type },
        updatedAt:        new Date(),
      };
    });

    try {
      const inserted = await db.insert(tiMalwareTable)
        .values(rows)
        .onConflictDoUpdate({
          target: tiMalwareTable.name,
          set: {
            description:  sql`excluded.description`,
            platforms:    sql`excluded.platforms`,
            actorNames:   sql`excluded.actor_names`,
            mitreId:      sql`excluded.mitre_id`,
            mitreUrl:     sql`excluded.mitre_url`,
            riskScore:    sql`GREATEST(ti_malware.risk_score, excluded.risk_score)`,
            updatedAt:    sql`NOW()`,
          },
        })
        .returning({ id: tiMalwareTable.id });
      malwareInserted += inserted.length;
    } catch (err) {
      logger.warn({ err }, "ATT&CK malware batch upsert error");
    }
  }

  // ── 4. Upsert TTPs (attack-patterns linked to actors) ────────────────────

  let ttpsInserted = 0;

  // For each actor, find their used attack-patterns
  for (const [stixId, dbId] of stixIdToDbId.entries()) {
    const rels = relBySrc.get(stixId) ?? [];
    const usedPatternIds = rels
      .filter(r => r.type === "uses")
      .map(r => r.target)
      .filter(t => t.startsWith("attack-pattern--"));

    if (usedPatternIds.length === 0) continue;

    const ttpRows = usedPatternIds.flatMap(patternId => {
      const pattern = byId.get(patternId);
      if (!pattern) return [];
      const killChain: any[] = pattern.kill_chain_phases ?? [];

      return killChain.map(phase => {
        const tacticId = phase.phase_name as string;
        const tacticName = TACTIC_MAP[tacticId] ?? tacticId;
        const mitreId = extractMitreId(pattern);
        const subtechniqueMatch = mitreId?.match(/^T\d+\.(\d+)$/);

        return {
          actorId:           dbId,
          tacticId:          tacticId,
          tacticName:        tacticName,
          techniqueId:       subtechniqueMatch ? mitreId!.split(".")[0]! : (mitreId ?? ""),
          techniqueName:     pattern.name as string,
          subtechniqueId:    subtechniqueMatch ? mitreId : null,
          subtechniqueName:  subtechniqueMatch ? pattern.name as string : null,
          description:       stixVal(pattern, "description").slice(0, 500) || null,
          detection:         stixVal(pattern, "x_mitre_detection").slice(0, 500) || null,
          platforms:         stixArr(pattern, "x_mitre_platforms"),
          source:            "mitre_attack",
        };
      });
    });

    if (ttpRows.length === 0) continue;

    // Remove existing TTPs for this actor and re-insert (simpler than upsert on complex key)
    const BATCH = 200;
    for (let i = 0; i < ttpRows.length; i += BATCH) {
      try {
        const inserted = await db.insert(tiActorTtpsTable)
          .values(ttpRows.slice(i, i + BATCH))
          .onConflictDoNothing()
          .returning({ id: tiActorTtpsTable.id });
        ttpsInserted += inserted.length;
      } catch (err) {
        logger.warn({ err, actorId: dbId }, "ATT&CK TTP batch insert error");
      }
    }
  }

  logger.info({ actorsInserted, campaignsInserted, malwareInserted, ttpsInserted }, "MITRE ATT&CK ingest complete");
  return {
    actors: actorsInserted,
    campaigns: campaignsInserted,
    malware: malwareInserted,
    ttps: ttpsInserted,
  };
}
