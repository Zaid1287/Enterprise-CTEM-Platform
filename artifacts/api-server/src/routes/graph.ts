import { Router } from "express";
import { eq, and, inArray } from "drizzle-orm";
import {
  db,
  assetsTable,
  findingsTable,
  tenantsTable,
} from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { getAmClientTenantIds } from "../lib/amScoping";

const router = Router();

/**
 * GET /graph/attack-surface
 *
 * Returns the tenant's attack surface as a Neo4j-compatible graph
 * (nodes with labels + properties, relationships with types).
 *
 * Node ID prefixes:
 *   org-<tenantId>         Organization
 *   asset-<id>             any asset type
 *   port-<assetId>-<port>  virtual Port node
 *   finding-<id>           vulnerability finding
 *   cve-<cve>              CVE reference (virtual, deduplicated)
 */
router.get("/graph/attack-surface", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const role = req.user!.role;
  const tenantId = req.user!.tenantId;

  // AM sees a combined graph of all their assigned client tenants
  let clientTenantIds: number[] = [];
  let isAm = false;
  if (role === "account_manager") {
    isAm = true;
    clientTenantIds = await getAmClientTenantIds(req.user!.userId);
    if (clientTenantIds.length === 0) {
      res.json({ nodes: [], relationships: [], meta: { nodeCount: 0, relationshipCount: 0, assetCount: 0, findingCount: 0, cveCount: 0 } });
      return;
    }
  }

  const assetWhere = isAm
    ? and(inArray(assetsTable.tenantId, clientTenantIds), eq(assetsTable.isActive, true))
    : and(eq(assetsTable.tenantId, tenantId), eq(assetsTable.isActive, true));

  const findingWhere = isAm
    ? and(inArray(findingsTable.tenantId, clientTenantIds), eq(findingsTable.isFalsePositive, false))
    : and(eq(findingsTable.tenantId, tenantId), eq(findingsTable.isFalsePositive, false));

  const tenantIds = isAm ? clientTenantIds : [tenantId];

  const [tenants, assets, findings] = await Promise.all([
    db.select().from(tenantsTable).where(inArray(tenantsTable.id, tenantIds)),
    db.select().from(assetsTable).where(assetWhere),
    db.select().from(findingsTable).where(findingWhere),
  ]);

  const tenantMap = new Map(tenants.map(t => [t.id, t]));

  const nodes: any[] = [];
  const relationships: any[] = [];
  const seenCves = new Set<string>();

  // ── Organization node(s) ───────────────────────────────────────────────────
  for (const t of tenants) {
    const orgId = `org-${t.id}`;
    nodes.push({
      id: orgId,
      labels: ["Organization"],
      properties: {
        name: t.name ?? "Organization",
        tenantId: t.id,
        plan: t.plan ?? "starter",
      },
    });
  }

  // ── Asset nodes + edges ────────────────────────────────────────────────────
  const assetMap = new Map(assets.map(a => [a.id, a]));
  const assetValueToId = new Map(assets.map(a => [a.value.toLowerCase(), `asset-${a.id}`]));

  for (const asset of assets) {
    const nodeId = `asset-${asset.id}`;
    const primaryLabel = capitalize(asset.type);

    nodes.push({
      id: nodeId,
      labels: [primaryLabel, "Asset"],
      properties: {
        name: asset.name,
        value: asset.value,
        type: asset.type,
        riskLevel: asset.riskLevel,
        ipAddress: asset.ipAddress,
        port: asset.port,
        businessImpact: asset.businessImpact,
        verificationStatus: asset.verificationStatus,
        lastScannedAt: asset.lastScannedAt,
      },
    });

    // Org → Asset (OWNS) — each asset links to its own tenant's org node
    relationships.push({
      id: `r-owns-${asset.id}`,
      type: "OWNS",
      startNodeId: `org-${asset.tenantId}`,
      endNodeId: nodeId,
    });

    // Subdomain/URL → parent domain (SUBDOMAIN_OF)
    if (asset.type === "subdomain" || asset.type === "url") {
      for (const parent of assets) {
        if (
          parent.id !== asset.id &&
          parent.type === "domain" &&
          asset.value.toLowerCase().endsWith(`.${parent.value.toLowerCase()}`)
        ) {
          relationships.push({
            id: `r-sub-${asset.id}-${parent.id}`,
            type: "SUBDOMAIN_OF",
            startNodeId: nodeId,
            endNodeId: `asset-${parent.id}`,
          });
          break; // one parent
        }
      }
    }

    // Asset → IP (RESOLVES_TO) — when the asset has an explicit IP and a matching IP asset exists
    if (asset.ipAddress && asset.type !== "ip") {
      const ipNodeId = assetValueToId.get(asset.ipAddress.toLowerCase());
      if (ipNodeId && ipNodeId !== nodeId) {
        relationships.push({
          id: `r-resolves-${asset.id}`,
          type: "RESOLVES_TO",
          startNodeId: nodeId,
          endNodeId: ipNodeId,
        });
      }
    }

    // IP → Port (EXPOSES) — creates a virtual Port node
    if (asset.type === "ip" && asset.port) {
      const portId = `port-${asset.id}-${asset.port}`;
      nodes.push({
        id: portId,
        labels: ["Port"],
        properties: { port: asset.port, protocol: "tcp", assetId: asset.id },
      });
      relationships.push({
        id: `r-exposes-${asset.id}`,
        type: "EXPOSES",
        startNodeId: nodeId,
        endNodeId: portId,
      });
    }
  }

  // ── Finding nodes + edges ──────────────────────────────────────────────────
  for (const f of findings) {
    // Only add if linked asset still exists
    if (!assetMap.has(f.assetId)) continue;

    const findingId = `finding-${f.id}`;
    nodes.push({
      id: findingId,
      labels: ["Vulnerability", "Finding"],
      properties: {
        title: f.title,
        severity: f.severity,
        status: f.status,
        cve: f.cve,
        cvss: f.cvss,
        epss: f.epss,
        isKev: f.isKev,
        riskScore: f.riskScore,
      },
    });

    // Asset → Finding (HAS_VULNERABILITY)
    relationships.push({
      id: `r-vuln-${f.id}`,
      type: "HAS_VULNERABILITY",
      startNodeId: `asset-${f.assetId}`,
      endNodeId: findingId,
    });

    // Finding → CVE (REFERENCES_CVE) — deduplicated virtual nodes
    if (f.cve) {
      const cveKey = f.cve.toUpperCase();
      const cveId = `cve-${cveKey.replace(/[^A-Z0-9-]/g, "")}`;
      if (!seenCves.has(cveKey)) {
        seenCves.add(cveKey);
        nodes.push({
          id: cveId,
          labels: ["CVE"],
          properties: { id: cveKey, url: `https://nvd.nist.gov/vuln/detail/${cveKey}` },
        });
      }
      relationships.push({
        id: `r-cve-${f.id}`,
        type: "REFERENCES_CVE",
        startNodeId: findingId,
        endNodeId: cveId,
      });
    }
  }

  res.json({
    nodes,
    relationships,
    meta: {
      nodeCount: nodes.length,
      relationshipCount: relationships.length,
      assetCount: assets.length,
      findingCount: findings.length,
      cveCount: seenCves.size,
    },
  });
});

function capitalize(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export default router;
