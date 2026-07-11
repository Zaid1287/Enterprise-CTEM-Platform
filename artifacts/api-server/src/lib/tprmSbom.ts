/**
 * TPRM SBOM Parser + OSV Vulnerability Enrichment
 *
 * Supports: CycloneDX JSON, CycloneDX XML, SPDX JSON, SPDX tag-value
 * OSV API: https://api.osv.dev/v1/query (free, no key required)
 */

import { logger } from "./logger";
import { orchestratedFetch } from "./scanOrchestrator";

export type SbomFormat = "cyclonedx_json" | "cyclonedx_xml" | "spdx_json" | "spdx_tag_value";

export interface SbomComponent {
  name:        string;
  version:     string | null;
  purl:        string | null;
  cpe:         string | null;
  licenses:    string[];
  supplier:    string | null;
  description: string | null;
  type:        string;
}

export interface OsvVuln {
  id:       string;
  summary:  string;
  severity: string;
  cvss:     number | null;
  aliases:  string[];
  fixed:    string | null;
}

export interface SbomComponentWithVulns {
  component: SbomComponent;
  vulns:     OsvVuln[];
  riskLevel: "critical" | "high" | "medium" | "low" | "none";
}

export interface SbomParseResult {
  format:      SbomFormat;
  specVersion: string | null;
  toolName:    string | null;
  components:  SbomComponent[];
}

// ── Detect format ─────────────────────────────────────────────────────────────

export function detectSbomFormat(content: string, fileName: string): SbomFormat {
  const lower = fileName.toLowerCase();
  if (lower.endsWith(".xml") || content.trimStart().startsWith("<")) return "cyclonedx_xml";
  if (lower.endsWith(".spdx") || lower.endsWith(".tv") || content.includes("SPDXVersion:")) return "spdx_tag_value";
  try {
    const obj = JSON.parse(content);
    if (obj.spdxVersion || obj.SPDXID) return "spdx_json";
    return "cyclonedx_json";
  } catch {
    if (content.includes("SPDXVersion:")) return "spdx_tag_value";
    return "cyclonedx_json";
  }
}

// ── CycloneDX JSON parser ─────────────────────────────────────────────────────

function parseCycloneDxJson(content: string): SbomParseResult {
  const obj = JSON.parse(content);
  const specVersion = obj.specVersion ?? null;
  const toolName = obj.metadata?.tools?.[0]?.name ?? obj.metadata?.tools?.components?.[0]?.name ?? null;
  const components: SbomComponent[] = [];

  function parseComponent(c: any): SbomComponent {
    const licenses: string[] = [];
    if (c.licenses) {
      for (const l of c.licenses) {
        const id = l.license?.id ?? l.license?.name ?? l.expression;
        if (id) licenses.push(id);
      }
    }
    return {
      name:        c.name ?? "unknown",
      version:     c.version ?? null,
      purl:        c.purl ?? null,
      cpe:         c.cpe ?? null,
      licenses,
      supplier:    c.supplier?.name ?? c.author ?? null,
      description: c.description ?? null,
      type:        c.type ?? "library",
    };
  }

  if (Array.isArray(obj.components)) {
    for (const c of obj.components) {
      components.push(parseComponent(c));
      if (Array.isArray(c.components)) {
        for (const sub of c.components) components.push(parseComponent(sub));
      }
    }
  }
  if (obj.metadata?.component) components.unshift(parseComponent(obj.metadata.component));

  return { format: "cyclonedx_json", specVersion, toolName, components };
}

// ── CycloneDX XML parser ──────────────────────────────────────────────────────

function parseCycloneDxXml(content: string): SbomParseResult {
  const components: SbomComponent[] = [];

  function extractTag(xml: string, tag: string): string | null {
    const m = xml.match(new RegExp(`<${tag}[^>]*>([^<]*)<\/${tag}>`, "i"));
    return m?.[1]?.trim() ?? null;
  }

  const specVersion = content.match(/specVersion="([^"]+)"/)?.[1]
    ?? content.match(/<specVersion>([^<]+)<\/specVersion>/i)?.[1]
    ?? null;
  const toolName = content.match(/<tools?>[\s\S]*?<name>([^<]+)<\/name>/i)?.[1] ?? null;

  const componentBlocks = [...content.matchAll(/<component[^>]*>([\s\S]*?)<\/component>/gi)];
  for (const block of componentBlocks) {
    const inner = block[1] ?? "";
    const licenses: string[] = [];
    const licenseMatches = [...inner.matchAll(/<id>([^<]+)<\/id>|<name>([^<]+)<\/name>/gi)];
    for (const lm of licenseMatches) {
      const id = lm[1] ?? lm[2];
      if (id && !licenses.includes(id)) licenses.push(id);
    }
    components.push({
      name:        extractTag(inner, "name") ?? "unknown",
      version:     extractTag(inner, "version"),
      purl:        extractTag(inner, "purl"),
      cpe:         extractTag(inner, "cpe"),
      licenses:    licenses.slice(0, 3),
      supplier:    null,
      description: extractTag(inner, "description"),
      type:        "library",
    });
  }

  return { format: "cyclonedx_xml", specVersion, toolName, components };
}

// ── SPDX JSON parser ──────────────────────────────────────────────────────────

function parseSpdxJson(content: string): SbomParseResult {
  const obj = JSON.parse(content);
  const specVersion = obj.spdxVersion ?? null;
  const toolName = obj.creationInfo?.creators?.find((c: string) => c.startsWith("Tool:"))?.replace("Tool:", "").trim() ?? null;
  const components: SbomComponent[] = [];

  for (const pkg of (obj.packages ?? [])) {
    let purl: string | null = null;
    let cpe:  string | null = null;
    const licenses: string[] = [];

    if (pkg.licenseConcluded && pkg.licenseConcluded !== "NOASSERTION") licenses.push(pkg.licenseConcluded);
    if (pkg.licenseDeclared && pkg.licenseDeclared !== "NOASSERTION" && !licenses.includes(pkg.licenseDeclared)) licenses.push(pkg.licenseDeclared);

    for (const ref of (pkg.externalRefs ?? [])) {
      if (ref.referenceType === "purl") purl = ref.referenceLocator;
      if (ref.referenceType === "cpe22Type" || ref.referenceType === "cpe23Type") cpe = ref.referenceLocator;
    }

    components.push({
      name:        pkg.name ?? "unknown",
      version:     pkg.versionInfo ?? null,
      purl,
      cpe,
      licenses,
      supplier:    pkg.supplier ?? pkg.originator ?? null,
      description: pkg.description ?? pkg.comment ?? null,
      type:        "library",
    });
  }

  return { format: "spdx_json", specVersion, toolName, components };
}

// ── SPDX tag-value parser ─────────────────────────────────────────────────────

function parseSpdxTagValue(content: string): SbomParseResult {
  const lines = content.split("\n");
  const specVersion = lines.find(l => l.startsWith("SPDXVersion:"))?.split(":")[1]?.trim() ?? null;
  const toolName = lines.find(l => l.startsWith("Creator: Tool:"))?.replace("Creator: Tool:", "").trim() ?? null;
  const components: SbomComponent[] = [];

  let current: Partial<SbomComponent> | null = null;
  for (const line of lines) {
    if (line.startsWith("PackageName:")) {
      if (current?.name) components.push({ name: current.name ?? "unknown", version: current.version ?? null, purl: current.purl ?? null, cpe: current.cpe ?? null, licenses: current.licenses ?? [], supplier: current.supplier ?? null, description: current.description ?? null, type: "library" });
      current = { name: line.replace("PackageName:", "").trim(), licenses: [] };
    } else if (line.startsWith("PackageVersion:") && current) {
      current.version = line.replace("PackageVersion:", "").trim();
    } else if (line.startsWith("ExternalRef: PACKAGE-MANAGER purl") && current) {
      current.purl = line.replace("ExternalRef: PACKAGE-MANAGER purl", "").trim();
    } else if (line.startsWith("ExternalRef: SECURITY cpe") && current) {
      current.cpe = line.split(" ").pop() ?? null;
    } else if (line.startsWith("PackageLicenseConcluded:") && current && !line.includes("NOASSERTION")) {
      current.licenses = [...(current.licenses ?? []), line.replace("PackageLicenseConcluded:", "").trim()];
    } else if (line.startsWith("PackageSupplier:") && current) {
      current.supplier = line.replace("PackageSupplier:", "").trim();
    }
  }
  if (current?.name) components.push({ name: current.name ?? "unknown", version: current.version ?? null, purl: current.purl ?? null, cpe: current.cpe ?? null, licenses: current.licenses ?? [], supplier: current.supplier ?? null, description: current.description ?? null, type: "library" });

  return { format: "spdx_tag_value", specVersion, toolName, components };
}

// ── Main parser ───────────────────────────────────────────────────────────────

export function parseSbom(content: string, format: SbomFormat): SbomParseResult {
  try {
    switch (format) {
      case "cyclonedx_json":  return parseCycloneDxJson(content);
      case "cyclonedx_xml":   return parseCycloneDxXml(content);
      case "spdx_json":       return parseSpdxJson(content);
      case "spdx_tag_value":  return parseSpdxTagValue(content);
    }
  } catch (err) {
    logger.error({ err, format }, "TPRM: SBOM parse error");
    return { format, specVersion: null, toolName: null, components: [] };
  }
}

// ── OSV API enrichment ────────────────────────────────────────────────────────

const OSV_API = "https://api.osv.dev/v1/query";
const OSV_BATCH_SIZE = 20;

async function queryOsv(component: SbomComponent): Promise<OsvVuln[]> {
  const body: any = {};
  if (component.purl) {
    body.package = { purl: component.purl };
    if (component.version) body.version = component.version;
  } else if (component.name) {
    body.package = { name: component.name, ecosystem: "npm" };
    if (component.version) body.version = component.version;
  } else {
    return [];
  }

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 10000);
    const res = await orchestratedFetch(OSV_API, {
      method:  "POST",
      signal:  ctrl.signal,
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body:    JSON.stringify(body),
    }, { intensity: "passive" });
    clearTimeout(t);
    if (!res.ok) return [];

    const data: any = await res.json().catch(() => null);
    if (!data?.vulns) return [];

    return data.vulns.slice(0, 20).map((v: any) => {
      let cvss: number | null = null;
      if (v.severity) {
        for (const s of v.severity) {
          if (s.type === "CVSS_V3" || s.type === "CVSS_V2") {
            const m = String(s.score ?? "").match(/AV:[^\s]+\/AC:[^\s]+\/[^\s]+ (\d+\.\d+)/);
            if (!cvss && m?.[1]) cvss = parseFloat(m[1]);
          }
        }
      }
      const aliases = (v.aliases ?? []) as string[];
      const cveId = aliases.find(a => a.startsWith("CVE-")) ?? v.id ?? "";
      const severity = cvss !== null
        ? (cvss >= 9 ? "critical" : cvss >= 7 ? "high" : cvss >= 4 ? "medium" : "low")
        : "medium";
      const fixed = v.affected?.[0]?.ranges?.[0]?.events?.find((e: any) => e.fixed)?.fixed ?? null;
      return { id: v.id, summary: v.summary ?? v.details ?? "No description", severity, cvss, aliases, fixed };
    });
  } catch {
    return [];
  }
}

export async function enrichSbomWithVulnerabilities(components: SbomComponent[]): Promise<SbomComponentWithVulns[]> {
  const results: SbomComponentWithVulns[] = [];

  for (let i = 0; i < components.length; i += OSV_BATCH_SIZE) {
    const batch = components.slice(i, i + OSV_BATCH_SIZE);
    const batchResults = await Promise.allSettled(batch.map(c => queryOsv(c)));

    for (let j = 0; j < batch.length; j++) {
      const component = batch[j]!;
      const vulns = batchResults[j]?.status === "fulfilled" ? (batchResults[j] as PromiseFulfilledResult<OsvVuln[]>).value : [];
      const riskLevel = calculateSbomRiskLevel(vulns);
      results.push({ component, vulns, riskLevel });
    }

    // Rate limit: small delay between batches
    if (i + OSV_BATCH_SIZE < components.length) {
      await new Promise(r => setTimeout(r, 500));
    }
  }

  return results;
}

export function calculateSbomRiskLevel(vulns: OsvVuln[]): "critical" | "high" | "medium" | "low" | "none" {
  if (vulns.length === 0) return "none";
  const maxCvss = Math.max(...vulns.map(v => v.cvss ?? 0));
  if (maxCvss >= 9 || vulns.some(v => v.severity === "critical")) return "critical";
  if (maxCvss >= 7 || vulns.some(v => v.severity === "high"))     return "high";
  if (maxCvss >= 4 || vulns.some(v => v.severity === "medium"))   return "medium";
  return "low";
}
