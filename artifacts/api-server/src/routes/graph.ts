import { Router } from "express";
import { eq, and, inArray } from "drizzle-orm";
import {
  db,
  assetsTable,
  findingsTable,
  tenantsTable,
} from "@workspace/db";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { getAmClientTenantIds } from "../lib/amScoping";

const router = Router();
router.use(denyExternalMembers);

/**
 * GET /graph/attack-surface
 *
 * Returns the tenant's attack surface as a Neo4j-compatible graph.
 *
 * Node ID prefixes:
 *   org-<tenantId>                    Organization
 *   asset-<id>                        any registered asset
 *   ip-virtual-<ip-slug>              auto-synthesised IP from DNS resolution
 *   port-<assetId>-<port>             Port node (from EXP-PORT findings)
 *   finding-<id>                      vulnerability finding
 *   cve-<cve>                         CVE (deduplicated, with CVSS/EPSS)
 *
 * Relationships:
 *   OWNS              org → asset
 *   SUBDOMAIN_OF      subdomain/url → domain
 *   RESOLVES_TO       domain/subdomain → IP
 *   EXPOSES           asset → Port  (built from EXP-PORT-* findings)
 *   HAS_VULNERABILITY asset → finding
 *   REFERENCES_CVE    finding → CVE
 */
router.get("/graph/attack-surface", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const role     = req.user!.role;
  const tenantId = req.user!.tenantId;

  // ── Derive the scope ────────────────────────────────────────────────────────
  let assetWhere: any;
  let findingWhere: any;
  let tenantIds: number[];

  if (role === "client") {
    // Client: only their explicitly assigned assets
    const assignedAssets = await db.select().from(assetsTable)
      .where(and(eq(assetsTable.assignedClientId, req.user!.userId), eq(assetsTable.isActive, true)));
    if (assignedAssets.length === 0) {
      res.json(emptyGraph());
      return;
    }
    const assignedIds       = assignedAssets.map(a => a.id);
    const assignedTenantIds = [...new Set(assignedAssets.map(a => a.tenantId))] as number[];

    const [tenants, findings] = await Promise.all([
      db.select().from(tenantsTable).where(inArray(tenantsTable.id, assignedTenantIds)),
      db.select().from(findingsTable).where(
        and(inArray(findingsTable.assetId, assignedIds), eq(findingsTable.isFalsePositive, false))
      ),
    ]);
    res.json(buildGraphPayload(tenants, assignedAssets, findings));
    return;
  }

  if (role === "account_manager") {
    const clientTenantIds = await getAmClientTenantIds(req.user!.userId);
    if (clientTenantIds.length === 0) { res.json(emptyGraph()); return; }
    tenantIds   = clientTenantIds;
    assetWhere  = and(inArray(assetsTable.tenantId, clientTenantIds), eq(assetsTable.isActive, true));
    findingWhere = and(inArray(findingsTable.tenantId, clientTenantIds), eq(findingsTable.isFalsePositive, false));
  } else {
    tenantIds    = [tenantId];
    assetWhere   = and(eq(assetsTable.tenantId, tenantId), eq(assetsTable.isActive, true));
    findingWhere = and(eq(findingsTable.tenantId, tenantId), eq(findingsTable.isFalsePositive, false));
  }

  const [tenants, assets, findings] = await Promise.all([
    db.select().from(tenantsTable).where(inArray(tenantsTable.id, tenantIds)),
    db.select().from(assetsTable).where(assetWhere),
    db.select().from(findingsTable).where(findingWhere),
  ]);

  res.json(buildGraphPayload(tenants, assets, findings));
});

// ── Shared graph builder ────────────────────────────────────────────────────

function emptyGraph() {
  return { nodes: [], relationships: [], meta: { nodeCount: 0, relationshipCount: 0, assetCount: 0, findingCount: 0, cveCount: 0 } };
}

function buildGraphPayload(
  tenants: (typeof tenantsTable.$inferSelect)[],
  assets:  (typeof assetsTable.$inferSelect)[],
  findings: (typeof findingsTable.$inferSelect)[],
) {
  const nodes: any[]         = [];
  const relationships: any[] = [];
  const seenCves             = new Set<string>();
  const seenVirtualIps       = new Set<string>();

  // ── Pre-pass 1: aggregate CVE stats (max CVSS, max EPSS) ──────────────────
  const cveStats = new Map<string, { maxCvss: number; maxEpss: number }>();
  for (const f of findings) {
    if (!f.cve) continue;
    const key  = f.cve.toUpperCase();
    const cvss = typeof f.cvss === "number" ? f.cvss : 0;
    const epss = typeof f.epss === "number" ? f.epss : 0;
    const prev = cveStats.get(key);
    cveStats.set(key, {
      maxCvss: Math.max(prev?.maxCvss ?? 0, cvss),
      maxEpss: Math.max(prev?.maxEpss ?? 0, epss),
    });
  }

  // ── Pre-pass 2: build port map from EXP-PORT-* findings ───────────────────
  // Each finding with cveId EXP-PORT-{port}-{slug} represents an open dangerous port.
  // We group these per asset so we can create Port nodes + EXPOSES edges below.
  const portsByAsset = new Map<number, Map<number, { protocol: string; service: string; version: string }>>();
  for (const f of findings) {
    if (!f.cve?.startsWith("EXP-PORT-")) continue;
    const m = f.cve.match(/^EXP-PORT-(\d+)-/);
    if (!m) continue;
    const port = parseInt(m[1], 10);
    if (isNaN(port)) continue;
    // Try to pull structured port data from the evidence field
    let protocol = "tcp";
    let service  = knownService(port);
    let version  = "";
    if (f.evidence) {
      try {
        const ev = JSON.parse(f.evidence as string);
        if (ev.protocol) protocol = ev.protocol;
        if (ev.service)  service  = ev.service;
        if (ev.version)  version  = ev.version;
      } catch {}
    }
    if (!portsByAsset.has(f.assetId)) portsByAsset.set(f.assetId, new Map());
    portsByAsset.get(f.assetId)!.set(port, { protocol, service, version });
  }

  // ── Organization nodes ─────────────────────────────────────────────────────
  for (const t of tenants) {
    nodes.push({
      id: `org-${t.id}`,
      labels: ["Organization"],
      properties: { name: t.name ?? "Organization", tenantId: t.id, plan: t.plan ?? "starter" },
    });
  }

  // ── Asset nodes + structural edges ────────────────────────────────────────
  const assetMap      = new Map(assets.map(a => [a.id, a]));
  const assetValueToId = new Map(assets.map(a => [a.value.toLowerCase(), `asset-${a.id}`]));

  for (const asset of assets) {
    const nodeId     = `asset-${asset.id}`;
    const nodeLabel  = capitalize(asset.type);

    nodes.push({
      id: nodeId,
      labels: [nodeLabel, "Asset"],
      properties: {
        name:               asset.name,
        value:              asset.value.toLowerCase(),
        type:               asset.type,
        riskLevel:          asset.riskLevel,
        ipAddress:          asset.ipAddress,
        businessImpact:     asset.businessImpact,
        verificationStatus: asset.verificationStatus,
        lastScannedAt:      asset.lastScannedAt,
      },
    });

    // OWNS (Org → Asset)
    relationships.push({ id: `r-owns-${asset.id}`, type: "OWNS", startNodeId: `org-${asset.tenantId}`, endNodeId: nodeId });

    // SUBDOMAIN_OF (subdomain/url → parent domain)
    if (asset.type === "subdomain" || asset.type === "url") {
      const assetVal = asset.value.toLowerCase();
      for (const parent of assets) {
        if (parent.id !== asset.id && parent.type === "domain" && assetVal.endsWith(`.${parent.value.toLowerCase()}`)) {
          relationships.push({ id: `r-sub-${asset.id}-${parent.id}`, type: "SUBDOMAIN_OF", startNodeId: nodeId, endNodeId: `asset-${parent.id}` });
          break;
        }
      }
    }

    // RESOLVES_TO (asset → IP)
    // If the asset has an IP and a matching IP asset exists → link to it.
    // If no IP asset exists → synthesise a virtual IP node so the edge is still visible.
    if (asset.ipAddress && asset.type !== "ip") {
      const normalised = asset.ipAddress.toLowerCase();
      const ipNodeId   = assetValueToId.get(normalised);
      if (ipNodeId && ipNodeId !== nodeId) {
        relationships.push({ id: `r-resolves-${asset.id}`, type: "RESOLVES_TO", startNodeId: nodeId, endNodeId: ipNodeId });
      } else if (!ipNodeId) {
        const vId = `ip-virtual-${normalised.replace(/[.:]/g, "-")}`;
        if (!seenVirtualIps.has(vId)) {
          seenVirtualIps.add(vId);
          nodes.push({
            id: vId,
            labels: ["Ip", "Asset"],
            properties: { name: asset.ipAddress, value: asset.ipAddress, type: "ip", riskLevel: "low", virtual: true },
          });
        }
        relationships.push({ id: `r-resolves-${asset.id}`, type: "RESOLVES_TO", startNodeId: nodeId, endNodeId: vId });
      }
    }

    // EXPOSES (asset → Port) — built from EXP-PORT-* findings
    const portMap = portsByAsset.get(asset.id);
    if (portMap && portMap.size > 0) {
      for (const [port, info] of portMap) {
        const portId = `port-${asset.id}-${port}`;
        nodes.push({
          id: portId,
          labels: ["Port"],
          properties: { port, protocol: info.protocol, service: info.service, version: info.version || null, assetId: asset.id },
        });
        relationships.push({ id: `r-exposes-${asset.id}-${port}`, type: "EXPOSES", startNodeId: nodeId, endNodeId: portId });
      }
    } else if (asset.type === "ip" && asset.port) {
      // Legacy: IP asset with a single port field set (no finding yet)
      const portId = `port-${asset.id}-${asset.port}`;
      nodes.push({
        id: portId,
        labels: ["Port"],
        properties: { port: asset.port, protocol: "tcp", service: knownService(asset.port), assetId: asset.id },
      });
      relationships.push({ id: `r-exposes-${asset.id}`, type: "EXPOSES", startNodeId: nodeId, endNodeId: portId });
    }
  }

  // ── Finding nodes + edges ──────────────────────────────────────────────────
  for (const f of findings) {
    if (!assetMap.has(f.assetId)) continue;

    const findingId = `finding-${f.id}`;
    nodes.push({
      id: findingId,
      labels: ["Vulnerability", "Finding"],
      properties: {
        title:      f.title,
        severity:   f.severity,
        status:     f.status,
        cve:        f.cve,
        cvss:       f.cvss,
        epss:       f.epss,
        isKev:      f.isKev,
        riskScore:  f.riskScore,
      },
    });
    relationships.push({ id: `r-vuln-${f.id}`, type: "HAS_VULNERABILITY", startNodeId: `asset-${f.assetId}`, endNodeId: findingId });

    // REFERENCES_CVE — enriched node with aggregated CVSS/EPSS + NVD URL
    if (f.cve) {
      const cveKey = f.cve.toUpperCase();
      const cveId  = `cve-${cveKey.replace(/[^A-Z0-9-]/g, "")}`;
      if (!seenCves.has(cveKey)) {
        seenCves.add(cveKey);
        const stats    = cveStats.get(cveKey);
        const isRealCve = /^CVE-\d{4}-\d+$/i.test(cveKey);
        nodes.push({
          id: cveId,
          labels: ["CVE"],
          properties: {
            id:     cveKey,
            cvss:   stats?.maxCvss ?? null,
            epss:   stats?.maxEpss ?? null,
            nvdUrl: isRealCve ? `https://nvd.nist.gov/vuln/detail/${cveKey}` : null,
          },
        });
      }
      relationships.push({ id: `r-cve-${f.id}`, type: "REFERENCES_CVE", startNodeId: findingId, endNodeId: cveId });
    }
  }

  return {
    nodes,
    relationships,
    meta: {
      nodeCount:         nodes.length,
      relationshipCount: relationships.length,
      assetCount:        assets.length,
      findingCount:      findings.length,
      cveCount:          seenCves.size,
    },
  };
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Best-effort well-known service name for common ports. */
function knownService(port: number): string {
  const svc: Record<number, string> = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    445: "smb", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    6379: "redis", 8080: "http-alt", 9200: "elasticsearch", 27017: "mongodb",
  };
  return svc[port] ?? "unknown";
}

export default router;
