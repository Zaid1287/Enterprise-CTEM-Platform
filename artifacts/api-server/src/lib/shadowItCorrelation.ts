/**
 * Shadow IT Correlation Engine
 *
 * Cross-references ALL discovered assets (subdomains, cloud buckets, email SaaS,
 * admin panels, shadow services, unauthorized tech) against the known asset
 * inventory and classifies each unknown as a Shadow IT finding.
 *
 * Called:
 *   1. After every pipeline scan completes (post-scan hook in pipelineScans.ts)
 *   2. By the beat scheduler daily job
 *   3. Via manual POST /api/shadow-it/scan trigger
 */
import { db, assetsTable, shadowItAssetsTable, shadowItSaasAppsTable, findingsTable, scanAssetResultsTable, discoveryResultsTable, technologyDetectionsTable } from "@workspace/db";
import { eq, and, inArray, desc, sql } from "drizzle-orm";
import { dispatchNotifications } from "./notifier";
import { logger } from "./logger";
import { runCtLogs, runDkimCheck } from "./passiveDiscovery";
import { runCloudRecon } from "./cloudRecon";
import { getPlatformSetting } from "../routes/platformSettings";

// ── SPF/DKIM → SaaS mapping ───────────────────────────────────────────────────

const SPF_INCLUDE_TO_SAAS: Record<string, { name: string; category: string; risk: string }> = {
  "sendgrid.net":              { name: "SendGrid",              category: "email",       risk: "medium" },
  "amazonses.com":             { name: "AWS SES",               category: "email",       risk: "low"    },
  "mailgun.org":               { name: "Mailgun",               category: "email",       risk: "medium" },
  "mailgun.net":               { name: "Mailgun",               category: "email",       risk: "medium" },
  "sparkpostmail.com":         { name: "SparkPost",             category: "email",       risk: "medium" },
  "mandrillapp.com":           { name: "Mailchimp/Mandrill",    category: "email",       risk: "medium" },
  "mailchimp.com":             { name: "Mailchimp",             category: "email",       risk: "medium" },
  "postmarkapp.com":           { name: "Postmark",              category: "email",       risk: "low"    },
  "protection.outlook.com":   { name: "Microsoft 365",         category: "email",       risk: "low"    },
  "outlook.com":               { name: "Microsoft 365",         category: "email",       risk: "low"    },
  "google.com":                { name: "Google Workspace",      category: "email",       risk: "low"    },
  "googlemail.com":            { name: "Google Workspace",      category: "email",       risk: "low"    },
  "zoho.com":                  { name: "Zoho Mail",             category: "email",       risk: "medium" },
  "salesforce.com":            { name: "Salesforce Email",      category: "crm",         risk: "medium" },
  "exacttarget.com":           { name: "Salesforce Marketing",  category: "marketing",   risk: "medium" },
  "hubspot.com":               { name: "HubSpot Email",         category: "crm",         risk: "medium" },
  "klaviyo.com":               { name: "Klaviyo",               category: "marketing",   risk: "medium" },
  "sendinblue.com":            { name: "Brevo (Sendinblue)",    category: "email",       risk: "medium" },
  "brevo.com":                 { name: "Brevo",                 category: "email",       risk: "medium" },
  "constantcontact.com":       { name: "Constant Contact",      category: "marketing",   risk: "medium" },
  "mailjet.com":               { name: "Mailjet",               category: "email",       risk: "medium" },
  "freshdesk.com":             { name: "Freshdesk",             category: "support",     risk: "medium" },
  "zendesk.com":               { name: "Zendesk",               category: "support",     risk: "medium" },
  "intercom.io":               { name: "Intercom",              category: "support",     risk: "medium" },
  "helpscout.net":             { name: "Help Scout",            category: "support",     risk: "low"    },
  "activecampaign.com":        { name: "ActiveCampaign",        category: "marketing",   risk: "medium" },
  "drip.com":                  { name: "Drip",                  category: "marketing",   risk: "medium" },
  "mailerlite.com":            { name: "MailerLite",            category: "email",       risk: "low"    },
  "mcsv.net":                  { name: "Mailchimp",             category: "email",       risk: "medium" },
  "spf.protection.outlook.com":{ name: "Microsoft 365",        category: "email",       risk: "low"    },
  "smtp.com":                  { name: "SMTP.com",              category: "email",       risk: "medium" },
};

const DKIM_SELECTOR_TO_SAAS: Record<string, { name: string; category: string }> = {
  "google":      { name: "Google Workspace",   category: "email"     },
  "s1":          { name: "Google Workspace",   category: "email"     },
  "s2":          { name: "Google Workspace",   category: "email"     },
  "selector1":   { name: "Microsoft 365",      category: "email"     },
  "selector2":   { name: "Microsoft 365",      category: "email"     },
  "sendgrid":    { name: "SendGrid",           category: "email"     },
  "s1024":       { name: "SendGrid",           category: "email"     },
  "s2048":       { name: "SendGrid",           category: "email"     },
  "mailchimp":   { name: "Mailchimp",          category: "email"     },
  "mandrill":    { name: "Mailchimp/Mandrill", category: "email"     },
  "m1":          { name: "Mailchimp",          category: "email"     },
  "k1":          { name: "Mailgun",            category: "email"     },
  "k2":          { name: "Mailgun",            category: "email"     },
  "pm":          { name: "Postmark",           category: "email"     },
  "sparkpost":   { name: "SparkPost",          category: "email"     },
  "mailjet":     { name: "Mailjet",            category: "email"     },
  "brevo":       { name: "Brevo (Sendinblue)", category: "email"     },
  "sm":          { name: "Brevo (Sendinblue)", category: "email"     },
  "zendesk":     { name: "Zendesk",            category: "support"   },
  "freshdesk":   { name: "Freshdesk",          category: "support"   },
  "salesforce":  { name: "Salesforce",         category: "crm"       },
  "hubspot":     { name: "HubSpot",            category: "crm"       },
  "klaviyo":     { name: "Klaviyo",            category: "marketing" },
  "intercom":    { name: "Intercom",           category: "support"   },
  "mxe":        { name: "Generic Mail Service", category: "email"   },
  "smtp":        { name: "Generic SMTP",       category: "email"     },
  "amazonses":   { name: "AWS SES",            category: "email"     },
  "dkim":        { name: "Generic Mail Service", category: "email"   },
  "dkim1":       { name: "Generic Mail Service", category: "email"   },
};

// ── Classification keywords ───────────────────────────────────────────────────

const DEV_KEYWORDS  = ["dev", "staging", "stage", "test", "qa", "uat", "demo", "sandbox", "preview", "beta", "alpha", "local", "develop", "internal-test"];
const OLD_KEYWORDS  = ["old", "backup", "bak", "legacy", "archive", "deprecated", "retired", "temp", "tmp", "unused"];

function classifySubdomainName(name: string): "development" | "forgotten" | "rogue" {
  const lower = name.toLowerCase();
  if (DEV_KEYWORDS.some(k => lower.includes(k))) return "development";
  if (OLD_KEYWORDS.some(k => lower.includes(k))) return "forgotten";
  return "rogue";
}

function isAdminPanelTitle(title: string): boolean {
  const t = title.toLowerCase();
  return t.includes("admin panel") || t.includes("admin console") || t.includes("management interface") ||
    t.includes("phpmyadmin") || t.includes("adminer") || t.includes("kibana") ||
    t.includes("grafana") || t.includes("jenkins") || t.includes("elasticsearch head") ||
    t.includes("rabbitmq") || t.includes("redis commander") || t.includes("mongo express") ||
    t.includes("default login") || t.includes("exposed panel") || t.includes("management console") ||
    t.includes("control panel") || t.includes("couchdb") || t.includes("solr admin");
}

// ── Risk scoring ──────────────────────────────────────────────────────────────

interface RiskFactors {
  type: string;
  classification: string;
  isPublic: boolean;
  hasOpenPorts: boolean;
  hasAdminPanel: boolean;
  hasAuthBypass: boolean;
  isListable: boolean;
  certAgeDays: number;
  httpStatus: number | null;
  severity?: string;
}

function calculateRiskScore(f: RiskFactors): { score: number; level: "critical" | "high" | "medium" | "low" | "info" } {
  let score = 30;

  if (f.type === "cloud_bucket")   score = f.isListable ? 85 : 65;
  else if (f.type === "admin_panel")   score = 75;
  else if (f.type === "shadow_service")  score = 60;
  else if (f.type === "subdomain")   score = 35;
  else if (f.type === "email_service")   score = 20;
  else if (f.type === "unauthorized_tech") score = 45;
  else if (f.type === "ip_asset")    score = 40;

  if (f.classification === "rogue")      score += 15;
  if (f.classification === "forgotten")  score += 10;
  if (f.classification === "development") score += 5;

  if (f.hasOpenPorts)   score += 15;
  if (f.hasAdminPanel)  score += 10;
  if (f.hasAuthBypass)  score += 20;
  if (f.isPublic)       score += 10;
  if (f.certAgeDays > 730) score += 10;
  else if (f.certAgeDays > 365) score += 5;
  if (f.httpStatus === 200) score += 5;
  if (f.severity === "critical") score = Math.max(score, 85);
  else if (f.severity === "high") score = Math.max(score, 70);

  score = Math.min(100, Math.max(0, score));
  const level = score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : score >= 20 ? "low" : "info";
  return { score, level };
}

// ── Internal types ────────────────────────────────────────────────────────────

interface ShadowAssetCandidate {
  name: string;
  type: string;
  classification: string;
  source: string;
  parentAssetId?: number | null;
  relatedScanId?: number | null;
  evidence: Record<string, unknown>;
  riskScore: number;
  riskLevel: string;
  hasOpenPorts: boolean;
  hasAdminPanel: boolean;
  hasAuthBypass: boolean;
  isPubliclyAccessible: boolean;
  certFirstSeen: Date | null;
}

interface ShadowSaasCandidate {
  appName: string;
  appCategory: string;
  idpSource: string;
  riskRating: string;
  evidence: Record<string, unknown>;
  discoveredViaAssetId?: number | null;
  relatedScanId?: number | null;
}

// ── SPF/DKIM signal extractors ────────────────────────────────────────────────

function detectSaasFromSpfInclude(include: string): { name: string; category: string; risk: string } | null {
  for (const [domain, saas] of Object.entries(SPF_INCLUDE_TO_SAAS)) {
    if (include.toLowerCase().includes(domain)) return saas;
  }
  return null;
}

function detectSaasFromDkimSelector(selector: string, record?: string): { name: string; category: string } | null {
  const lower = selector.toLowerCase();
  const match = DKIM_SELECTOR_TO_SAAS[lower];
  if (match) return match;
  for (const [key, saas] of Object.entries(DKIM_SELECTOR_TO_SAAS)) {
    if (lower.startsWith(key)) return saas;
  }
  if (record && record.includes("sendgrid")) return DKIM_SELECTOR_TO_SAAS["sendgrid"];
  if (record && record.includes("mailchimp")) return DKIM_SELECTOR_TO_SAAS["mailchimp"];
  if (record && record.includes("amazonses")) return DKIM_SELECTOR_TO_SAAS["amazonses"];
  return null;
}

// ── Upsert helpers ────────────────────────────────────────────────────────────

async function upsertShadowAssets(tenantId: number, candidates: ShadowAssetCandidate[]): Promise<number> {
  if (candidates.length === 0) return 0;
  let inserted = 0;
  for (const c of candidates) {
    try {
      await db.insert(shadowItAssetsTable).values({
        tenantId,
        name: c.name.slice(0, 512),
        type: c.type,
        classification: c.classification,
        source: c.source,
        parentAssetId: c.parentAssetId ?? null,
        relatedScanId: c.relatedScanId ?? null,
        evidence: c.evidence as any,
        riskScore: c.riskScore,
        riskLevel: c.riskLevel,
        hasOpenPorts: c.hasOpenPorts,
        hasAdminPanel: c.hasAdminPanel,
        hasAuthBypass: c.hasAuthBypass,
        isPubliclyAccessible: c.isPubliclyAccessible,
        certFirstSeen: c.certFirstSeen,
        status: "new",
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
      }).onConflictDoUpdate({
        target: [shadowItAssetsTable.tenantId, shadowItAssetsTable.name, shadowItAssetsTable.type],
        set: {
          lastSeenAt: new Date(),
          evidence: c.evidence as any,
          riskScore: c.riskScore,
          riskLevel: c.riskLevel,
          hasOpenPorts: c.hasOpenPorts,
          hasAdminPanel: c.hasAdminPanel,
          hasAuthBypass: c.hasAuthBypass,
          isPubliclyAccessible: c.isPubliclyAccessible,
          relatedScanId: c.relatedScanId ?? null,
          updatedAt: new Date(),
        },
      });
      inserted++;
    } catch (err) {
      logger.debug({ err, name: c.name }, "Shadow IT asset upsert failed (non-fatal)");
    }
  }
  return inserted;
}

async function upsertShadowSaasApps(tenantId: number, candidates: ShadowSaasCandidate[]): Promise<number> {
  if (candidates.length === 0) return 0;
  let inserted = 0;
  for (const c of candidates) {
    try {
      await db.insert(shadowItSaasAppsTable).values({
        tenantId,
        appName: c.appName.slice(0, 256),
        appCategory: c.appCategory,
        idpSource: c.idpSource,
        riskRating: c.riskRating,
        evidence: c.evidence as any,
        discoveredViaAssetId: c.discoveredViaAssetId ?? null,
        relatedScanId: c.relatedScanId ?? null,
        isSanctioned: false,
        status: "new",
      }).onConflictDoUpdate({
        target: [shadowItSaasAppsTable.tenantId, shadowItSaasAppsTable.appName, shadowItSaasAppsTable.idpSource],
        set: {
          evidence: c.evidence as any,
          updatedAt: new Date(),
        },
      });
      inserted++;
    } catch (err) {
      logger.debug({ err, appName: c.appName }, "Shadow IT SaaS app upsert failed (non-fatal)");
    }
  }
  return inserted;
}

// ── Main post-scan correlation (called after every pipeline scan) ─────────────

export async function runShadowItPostScanCorrelation(
  tenantId: number,
  scanId: number,
  assetIds: number[],
): Promise<void> {
  try {
    const [knownAssets, sarRows, scanFindings, discoveryRows, techDetections] = await Promise.all([
      db.select({ id: assetsTable.id, name: assetsTable.name, value: assetsTable.value, ipAddress: assetsTable.ipAddress })
        .from(assetsTable).where(eq(assetsTable.tenantId, tenantId)),
      db.select().from(scanAssetResultsTable).where(eq(scanAssetResultsTable.scanId, scanId)),
      db.select({ id: findingsTable.id, cve: findingsTable.cve, title: findingsTable.title, severity: findingsTable.severity, assetId: findingsTable.assetId, description: findingsTable.description })
        .from(findingsTable).where(eq(findingsTable.scanId, scanId)),
      assetIds.length > 0
        ? db.select().from(discoveryResultsTable)
            .where(inArray(discoveryResultsTable.assetId, assetIds))
            .orderBy(desc(discoveryResultsTable.createdAt)).limit(500)
        : db.select().from(discoveryResultsTable).where(sql`false`),
      assetIds.length > 0
        ? db.select({ assetId: technologyDetectionsTable.assetId, technology: technologyDetectionsTable.technology, category: technologyDetectionsTable.category, version: technologyDetectionsTable.version, confidence: technologyDetectionsTable.confidence })
            .from(technologyDetectionsTable)
            .where(and(inArray(technologyDetectionsTable.assetId, assetIds), eq(technologyDetectionsTable.scanId, scanId)))
        : db.select({ assetId: technologyDetectionsTable.assetId, technology: technologyDetectionsTable.technology, category: technologyDetectionsTable.category, version: technologyDetectionsTable.version, confidence: technologyDetectionsTable.confidence })
            .from(technologyDetectionsTable).where(sql`false`),
    ]);

    const knownNames = new Set<string>();
    for (const a of knownAssets) {
      if (a.name)      knownNames.add(a.name.toLowerCase());
      if (a.value)     knownNames.add(a.value.toLowerCase());
      if (a.ipAddress) knownNames.add(a.ipAddress.toLowerCase());
    }

    function isKnown(name: string): boolean {
      return knownNames.has(name.toLowerCase());
    }

    const candidates: ShadowAssetCandidate[] = [];
    const saasCandidates: ShadowSaasCandidate[] = [];

    // ── 1. Subdomains from scan_asset_results ─────────────────────────────────
    for (const sar of sarRows) {
      const parentAssetId = sar.assetId;

      if (sar.subdomains) {
        const subs = sar.subdomains as Array<{ name?: string; ip?: string; status?: string; httpStatus?: number; cdnProvider?: string | null; sources?: string[]; webServer?: string | null }>;
        for (const sub of subs) {
          const name = sub.name?.toLowerCase();
          if (!name || isKnown(name)) continue;
          const classification = classifySubdomainName(name);
          const isLive = sub.status === "active" || (sub.httpStatus != null && sub.httpStatus < 500);
          const { score, level } = calculateRiskScore({
            type: "subdomain", classification, isPublic: isLive,
            hasOpenPorts: false, hasAdminPanel: false, hasAuthBypass: false,
            isListable: false, certAgeDays: 0, httpStatus: sub.httpStatus ?? null,
          });
          candidates.push({
            name, type: "subdomain", classification, source: "subdomain_enum",
            parentAssetId, relatedScanId: scanId,
            evidence: { ip: sub.ip, status: sub.status, httpStatus: sub.httpStatus, webServer: sub.webServer, cdnProvider: sub.cdnProvider, discoveredBy: sub.sources },
            riskScore: score, riskLevel: level,
            hasOpenPorts: false, hasAdminPanel: false, hasAuthBypass: false,
            isPubliclyAccessible: isLive, certFirstSeen: null,
          });
        }
      }

      // ── 2. Cloud buckets from cloud_recon ─────────────────────────────────
      if (sar.cloudRecon) {
        const cr = sar.cloudRecon as { buckets?: Array<{ name: string; provider: string; url: string; status: string; isPublic: boolean; isListable: boolean; fileCount?: number; sampleFiles?: string[]; region?: string }>; firebase?: Array<{ name: string; url: string; status: string; isPublic: boolean; dataPreview?: string; dataKeys?: string[] }> };

        for (const bucket of (cr.buckets ?? [])) {
          if (!bucket.isPublic && !bucket.isListable) continue;
          const bucketName = `${bucket.provider}:${bucket.name}`;
          const { score, level } = calculateRiskScore({
            type: "cloud_bucket", classification: "cloud", isPublic: bucket.isPublic,
            hasOpenPorts: false, hasAdminPanel: false, hasAuthBypass: false,
            isListable: bucket.isListable, certAgeDays: 0, httpStatus: 200,
          });
          candidates.push({
            name: bucketName, type: "cloud_bucket", classification: "cloud",
            source: "cloud_recon", parentAssetId, relatedScanId: scanId,
            evidence: { provider: bucket.provider, bucketName: bucket.name, url: bucket.url, status: bucket.status, isPublic: bucket.isPublic, isListable: bucket.isListable, fileCount: bucket.fileCount, sampleFiles: (bucket.sampleFiles ?? []).slice(0, 5), region: bucket.region },
            riskScore: score, riskLevel: level,
            hasOpenPorts: false, hasAdminPanel: false, hasAuthBypass: false,
            isPubliclyAccessible: true, certFirstSeen: null,
          });
        }

        for (const fb of (cr.firebase ?? [])) {
          if (!fb.isPublic) continue;
          const { score, level } = calculateRiskScore({
            type: "cloud_bucket", classification: "cloud", isPublic: true,
            hasOpenPorts: false, hasAdminPanel: false, hasAuthBypass: true,
            isListable: true, certAgeDays: 0, httpStatus: 200,
          });
          candidates.push({
            name: `firebase:${fb.name}`, type: "cloud_bucket", classification: "cloud",
            source: "cloud_recon", parentAssetId, relatedScanId: scanId,
            evidence: { provider: "firebase", name: fb.name, url: fb.url, status: fb.status, isPublic: true, dataPreview: fb.dataPreview?.slice(0, 200), dataKeys: fb.dataKeys },
            riskScore: score, riskLevel: level,
            hasOpenPorts: false, hasAdminPanel: true, hasAuthBypass: true,
            isPubliclyAccessible: true, certFirstSeen: null,
          });
        }
      }

      // ── 3. Nuclei admin panel / default login findings ────────────────────
      for (const f of scanFindings) {
        if (!f.title || f.assetId !== sar.assetId) continue;
        if (!isAdminPanelTitle(f.title)) continue;
        const hasAuthBypass = /no auth|unauthenticated|bypass|no password|default cred/i.test(f.title + " " + (f.description ?? ""));
        const { score, level } = calculateRiskScore({
          type: "admin_panel", classification: "rogue", isPublic: true,
          hasOpenPorts: false, hasAdminPanel: true, hasAuthBypass,
          isListable: false, certAgeDays: 0, httpStatus: 200,
          severity: f.severity,
        });
        candidates.push({
          name: `admin:${f.title.slice(0, 120)}`,
          type: "admin_panel", classification: "rogue", source: "nuclei",
          parentAssetId, relatedScanId: scanId,
          evidence: { findingId: f.id, title: f.title, severity: f.severity, description: (f.description ?? "").slice(0, 500) },
          riskScore: score, riskLevel: level,
          hasOpenPorts: false, hasAdminPanel: true, hasAuthBypass,
          isPubliclyAccessible: true, certFirstSeen: null,
        });
      }

      // ── 4. Shadow services — dangerous port findings on scan assets ────────
      for (const f of scanFindings) {
        if (!f.cve?.startsWith("EXP-PORT-") || f.assetId !== sar.assetId) continue;
        const portMatch = f.cve.match(/EXP-PORT-(\d+)/);
        const port = portMatch ? portMatch[1] : "?";
        const { score, level } = calculateRiskScore({
          type: "shadow_service", classification: "rogue", isPublic: true,
          hasOpenPorts: true, hasAdminPanel: false, hasAuthBypass: false,
          isListable: false, certAgeDays: 0, httpStatus: null,
          severity: f.severity,
        });
        const assetData = knownAssets.find(a => a.id === sar.assetId);
        const assetName = assetData?.name ?? assetData?.value ?? `asset-${sar.assetId}`;
        candidates.push({
          name: `port:${port}@${assetName}`,
          type: "shadow_service", classification: "rogue", source: "port_scan",
          parentAssetId, relatedScanId: scanId,
          evidence: { port, findingId: f.id, title: f.title, severity: f.severity, description: (f.description ?? "").slice(0, 300) },
          riskScore: score, riskLevel: level,
          hasOpenPorts: true, hasAdminPanel: false, hasAuthBypass: false,
          isPubliclyAccessible: true, certFirstSeen: null,
        });
      }

      // ── 5. Unauthorized tech from tech detections ─────────────────────────
      const HIGH_RISK_TECH = new Set(["elasticsearch", "kibana", "mongodb", "redis", "couchdb", "cassandra", "grafana", "jenkins", "rabbitmq", "memcached", "phpmyadmin", "adminer", "webmin", "tomcat-manager", "glassfish", "jboss", "apache-struts"]);
      for (const td of techDetections.filter(t => t.assetId === sar.assetId)) {
        if (!HIGH_RISK_TECH.has((td.technology ?? "").toLowerCase())) continue;
        const { score, level } = calculateRiskScore({
          type: "unauthorized_tech", classification: "rogue", isPublic: true,
          hasOpenPorts: true, hasAdminPanel: false, hasAuthBypass: false,
          isListable: false, certAgeDays: 0, httpStatus: null,
        });
        const assetData = knownAssets.find(a => a.id === sar.assetId);
        const assetName = assetData?.name ?? `asset-${sar.assetId}`;
        candidates.push({
          name: `tech:${td.technology}@${assetName}`,
          type: "unauthorized_tech", classification: "unauthorized_stack", source: "tech_detect",
          parentAssetId, relatedScanId: scanId,
          evidence: { technology: td.technology, category: td.category, version: td.version, confidence: td.confidence },
          riskScore: score, riskLevel: level,
          hasOpenPorts: true, hasAdminPanel: false, hasAuthBypass: false,
          isPubliclyAccessible: true, certFirstSeen: null,
        });
      }
    }

    // ── 6. SPF / DKIM shadow SaaS signals from discovery_results ─────────────
    for (const dr of discoveryRows) {
      const data = dr.data as Record<string, unknown> | null;
      if (!data) continue;

      if (dr.source === "dkim_check") {
        const found = (data.found as Array<{ selector: string; value?: string; record?: string }> | undefined) ?? [];
        for (const f of found) {
          const saas = detectSaasFromDkimSelector(f.selector, f.record ?? f.value);
          if (saas) {
            saasCandidates.push({
              appName: saas.name,
              appCategory: saas.category,
              idpSource: "dkim_check",
              riskRating: "low",
              evidence: { selector: f.selector, record: (f.record ?? f.value ?? "").slice(0, 200) },
              discoveredViaAssetId: dr.assetId,
              relatedScanId: scanId,
            });
          }
        }
      }

      // SPF includes may come from various source names
      const spfIncludes: string[] = [];
      if (data.includes && Array.isArray(data.includes)) spfIncludes.push(...data.includes);
      if (data.spfIncludes && Array.isArray(data.spfIncludes)) spfIncludes.push(...data.spfIncludes);
      if (data.mechanisms && Array.isArray(data.mechanisms)) {
        for (const m of data.mechanisms as string[]) {
          if (m.startsWith("include:")) spfIncludes.push(m.replace("include:", ""));
        }
      }
      for (const inc of spfIncludes) {
        const saas = detectSaasFromSpfInclude(inc);
        if (saas) {
          saasCandidates.push({
            appName: saas.name,
            appCategory: saas.category,
            idpSource: "spf_dkim",
            riskRating: saas.risk,
            evidence: { spfInclude: inc, discoverySource: dr.source },
            discoveredViaAssetId: dr.assetId,
            relatedScanId: scanId,
          });
        }
      }

      // Parse SPF from DNS TXT records stored in discovery_results
      if (dr.source === "ct_logs" || dr.source === "asn_lookup") {
        // Extract cert first-seen dates for known shadow subdomains
        const certs = (data.certs as Array<{ name?: string; notBefore?: string }> | undefined) ?? [];
        for (const cert of certs) {
          if (!cert.name || isKnown(cert.name)) continue;
          // Update certFirstSeen for already-added subdomain candidates
          const certName = cert.name;
          const match = candidates.find(c => c.name === certName.toLowerCase() && c.type === "subdomain");
          if (match && cert.notBefore) {
            match.certFirstSeen = new Date(cert.notBefore);
            const ageDays = (Date.now() - match.certFirstSeen.getTime()) / 86_400_000;
            if (ageDays > 365) {
              match.classification = "forgotten";
              const { score, level } = calculateRiskScore({ ...match as any, certAgeDays: ageDays, isPublic: match.isPubliclyAccessible, isListable: false });
              match.riskScore = score; match.riskLevel = level;
            }
          }
        }
      }
    }

    // ── 7. Upsert all discovered Shadow IT assets ─────────────────────────────
    const [assetCount, saasCount] = await Promise.all([
      upsertShadowAssets(tenantId, candidates),
      upsertShadowSaasApps(tenantId, saasCandidates),
    ]);

    logger.info({ tenantId, scanId, assetCount, saasCount }, "Shadow IT post-scan correlation complete");

    // ── 8. Dispatch alerts for new critical/high shadow assets ─────────────────
    const highRisk = candidates.filter(c => c.riskLevel === "critical" || c.riskLevel === "high");
    if (highRisk.length > 0) {
      setImmediate(() => {
        dispatchNotifications({
          tenantId, eventType: "shadow_it_discovered",
          title: `Shadow IT Discovered: ${highRisk.length} high-risk asset${highRisk.length > 1 ? "s" : ""}`,
          message: `${highRisk.length} unknown asset${highRisk.length > 1 ? "s were" : " was"} discovered outside your registered inventory during the latest scan. Immediate review recommended.\n\nTop finding: ${highRisk[0].name} (${highRisk[0].type}, ${highRisk[0].riskLevel} risk — ${highRisk[0].classification})`,
          severity: highRisk.some(c => c.riskLevel === "critical") ? "critical" : "high",
          findingsCount: highRisk.length,
          criticalCount: highRisk.filter(c => c.riskLevel === "critical").length,
          highCount: highRisk.filter(c => c.riskLevel === "high").length,
          scanId,
        }).catch(err => logger.warn({ err }, "Shadow IT alert dispatch failed"));
      });
    }

  } catch (err) {
    logger.warn({ err, tenantId, scanId }, "Shadow IT post-scan correlation failed (non-fatal)");
  }
}

// ── Standalone Shadow IT discovery (beat scheduler / manual trigger) ──────────

export async function runShadowItDiscovery(
  tenantId: number,
  seedAssetId?: number,
): Promise<{ assetsFound: number; saasFound: number }> {
  try {
    // Find domain assets to scan for this tenant
    const domainAssets = await db.select({
      id: assetsTable.id, name: assetsTable.name, value: assetsTable.value,
    }).from(assetsTable).where(and(
      eq(assetsTable.tenantId, tenantId),
      sql`${assetsTable.type} IN ('domain', 'subdomain', 'url')`,
    )).limit(20);

    const targets = seedAssetId
      ? domainAssets.filter(a => a.id === seedAssetId)
      : domainAssets;

    if (targets.length === 0) return { assetsFound: 0, saasFound: 0 };

    const knownAssets = await db.select({ id: assetsTable.id, name: assetsTable.name, value: assetsTable.value, ipAddress: assetsTable.ipAddress })
      .from(assetsTable).where(eq(assetsTable.tenantId, tenantId));

    const knownNames = new Set<string>();
    for (const a of knownAssets) {
      if (a.name)      knownNames.add(a.name.toLowerCase());
      if (a.value)     knownNames.add(a.value.toLowerCase());
      if (a.ipAddress) knownNames.add(a.ipAddress.toLowerCase());
    }

    const [shodanKey, githubToken] = await Promise.all([
      getPlatformSetting("shodan_api_key").catch(() => null),
      getPlatformSetting("github_token").catch(() => null),
    ]);

    const allCandidates: ShadowAssetCandidate[] = [];
    const allSaasCandidates: ShadowSaasCandidate[] = [];

    for (const asset of targets.slice(0, 5)) {
      const target = asset.value ?? asset.name;
      if (!target) continue;

      try {
        // Run passive discovery in parallel: CT logs + DKIM (most reliable without scan)
        const [ctResult, dkimResult, cloudResult] = await Promise.allSettled([
          runCtLogs(target),
          runDkimCheck(target),
          runCloudRecon(target),
        ]);

        // CT logs → new subdomains
        if (ctResult.status === "fulfilled" && ctResult.value.data) {
          const certs = (ctResult.value.data as any).certs ?? [];
          for (const cert of certs) {
            const name = (cert.name ?? "").toLowerCase();
            if (!name || knownNames.has(name)) continue;
            const certDate = cert.notBefore ? new Date(cert.notBefore) : null;
            const ageDays = certDate ? (Date.now() - certDate.getTime()) / 86_400_000 : 0;
            let classification = classifySubdomainName(name);
            if (ageDays > 365 && classification !== "development") classification = "forgotten";
            const { score, level } = calculateRiskScore({
              type: "subdomain", classification, isPublic: false,
              hasOpenPorts: false, hasAdminPanel: false, hasAuthBypass: false,
              isListable: false, certAgeDays: ageDays, httpStatus: null,
            });
            allCandidates.push({
              name, type: "subdomain", classification, source: "ct_logs",
              parentAssetId: asset.id, relatedScanId: null,
              evidence: { certIssuer: cert.issuer, notBefore: cert.notBefore, notAfter: cert.notAfter, discoveredBy: "certificate_transparency" },
              riskScore: score, riskLevel: level,
              hasOpenPorts: false, hasAdminPanel: false, hasAuthBypass: false,
              isPubliclyAccessible: false, certFirstSeen: certDate,
            });
          }
        }

        // DKIM → SaaS signals
        if (dkimResult.status === "fulfilled" && dkimResult.value.data) {
          const found = (dkimResult.value.data as any).found ?? [];
          for (const f of found) {
            const saas = detectSaasFromDkimSelector(f.selector, f.record ?? f.value);
            if (saas) {
              allSaasCandidates.push({
                appName: saas.name, appCategory: saas.category,
                idpSource: "dkim_check", riskRating: "low",
                evidence: { selector: f.selector, record: (f.record ?? f.value ?? "").slice(0, 200), target },
                discoveredViaAssetId: asset.id, relatedScanId: null,
              });
            }
          }
        }

        // Cloud recon → public buckets
        if (cloudResult.status === "fulfilled") {
          const cr = cloudResult.value;
          for (const bucket of cr.buckets.filter(b => b.isPublic || b.isListable)) {
            const bucketName = `${bucket.provider}:${bucket.name}`;
            const { score, level } = calculateRiskScore({
              type: "cloud_bucket", classification: "cloud", isPublic: bucket.isPublic,
              hasOpenPorts: false, hasAdminPanel: false, hasAuthBypass: false,
              isListable: bucket.isListable, certAgeDays: 0, httpStatus: 200,
            });
            allCandidates.push({
              name: bucketName, type: "cloud_bucket", classification: "cloud",
              source: "cloud_recon", parentAssetId: asset.id, relatedScanId: null,
              evidence: { provider: bucket.provider, bucketName: bucket.name, url: bucket.url, isPublic: bucket.isPublic, isListable: bucket.isListable, fileCount: bucket.fileCount, sampleFiles: (bucket.sampleFiles ?? []).slice(0, 5) },
              riskScore: score, riskLevel: level,
              hasOpenPorts: false, hasAdminPanel: false, hasAuthBypass: false,
              isPubliclyAccessible: true, certFirstSeen: null,
            });
          }
          for (const fb of cr.firebase.filter(f => f.isPublic)) {
            allCandidates.push({
              name: `firebase:${fb.name}`, type: "cloud_bucket", classification: "cloud",
              source: "cloud_recon", parentAssetId: asset.id, relatedScanId: null,
              evidence: { provider: "firebase", name: fb.name, url: fb.url, isPublic: true, dataPreview: fb.dataPreview?.slice(0, 200) },
              riskScore: 90, riskLevel: "critical",
              hasOpenPorts: false, hasAdminPanel: true, hasAuthBypass: true,
              isPubliclyAccessible: true, certFirstSeen: null,
            });
          }
        }
      } catch (err) {
        logger.debug({ err, target }, "Shadow IT standalone scan target failed (non-fatal)");
      }
    }

    const [assetCount, saasCount] = await Promise.all([
      upsertShadowAssets(tenantId, allCandidates),
      upsertShadowSaasApps(tenantId, allSaasCandidates),
    ]);

    // Alert on high/critical new findings
    const highRisk = allCandidates.filter(c => c.riskLevel === "critical" || c.riskLevel === "high");
    if (highRisk.length > 0) {
      setImmediate(() => {
        dispatchNotifications({
          tenantId, eventType: "shadow_it_discovered",
          title: `Shadow IT Daily Scan: ${highRisk.length} high-risk unknown asset${highRisk.length > 1 ? "s" : ""}`,
          message: `Daily Shadow IT scan found ${highRisk.length} high-risk unknown asset${highRisk.length > 1 ? "s" : ""} not in your registered inventory.\n\nTop finding: ${highRisk[0].name} (${highRisk[0].type}, ${highRisk[0].riskLevel} risk)`,
          severity: highRisk.some(c => c.riskLevel === "critical") ? "critical" : "high",
          findingsCount: highRisk.length,
          criticalCount: highRisk.filter(c => c.riskLevel === "critical").length,
          highCount: highRisk.filter(c => c.riskLevel === "high").length,
        }).catch(err => logger.warn({ err }, "Shadow IT alert dispatch failed"));
      });
    }

    logger.info({ tenantId, assetCount, saasCount }, "Shadow IT standalone discovery complete");
    return { assetsFound: assetCount, saasFound: saasCount };
  } catch (err) {
    logger.warn({ err, tenantId }, "Shadow IT standalone discovery failed");
    return { assetsFound: 0, saasFound: 0 };
  }
}
