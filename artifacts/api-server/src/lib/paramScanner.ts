import { exec } from "child_process";
import { promisify } from "util";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { logger } from "./logger";

const execAsync = promisify(exec);

// ── Types ──────────────────────────────────────────────────────────────────────

export interface DiscoveredParam {
  url: string;
  params: string[];
  source: "arjun" | "uro" | "linkfinder" | "manual";
  method: "GET" | "POST";
}

export interface ParamScanResult {
  discoveredParams: DiscoveredParam[];
  jsEndpoints: string[];
  filteredUrls: string[];
  stats: {
    urlsAnalyzed: number;
    paramsFound: number;
    jsEndpointsFound: number;
    urlsFiltered: number;
  };
}

// ── Arjun ─────────────────────────────────────────────────────────────────────

async function runArjun(url: string): Promise<DiscoveredParam[]> {
  const outFile = path.join(os.tmpdir(), `arjun-${Date.now()}.json`);
  try {
    const safeUrl = url.replace(/"/g, "").slice(0, 500);
    await execAsync(
      `python3 -m arjun -u "${safeUrl}" -oJ "${outFile}" -t 5 --stable -q 2>/dev/null`,
      { timeout: 90_000, env: { ...process.env, HOME: process.env.HOME ?? "/home/runner" } }
    );
    if (!fs.existsSync(outFile)) return [];
    const raw = fs.readFileSync(outFile, "utf8");
    const data = JSON.parse(raw);
    const params: string[] = Array.isArray(data)
      ? data.map((p: any) => typeof p === "string" ? p : (p.param ?? p.name ?? String(p)))
      : (data.params ?? data.results ?? []);
    if (!params.length) return [];
    return [{ url, params: params.filter(Boolean), source: "arjun", method: "GET" }];
  } catch (err) {
    logger.warn({ url, err }, "Arjun param discovery failed");
    return [];
  } finally {
    try { if (fs.existsSync(outFile)) fs.unlinkSync(outFile); } catch {}
  }
}

// ── URO (URL de-duplication) ──────────────────────────────────────────────────

async function runUro(urls: string[]): Promise<string[]> {
  if (urls.length === 0) return [];
  try {
    // Use uro as a Python module via stdin/stdout
    const script = `
import sys
sys.path.insert(0, '/home/runner/workspace/.pythonlibs/lib/python3.11/site-packages')
try:
    from uro import main as uro_main
    import io, contextlib
    inp = sys.stdin.read()
    out = io.StringIO()
    sys.argv = ['uro']
    sys.stdin = io.StringIO(inp)
    with contextlib.redirect_stdout(out):
        uro_main()
    print(out.getvalue(), end='')
except Exception as e:
    # fallback: print all
    print(inp)
`;
    const { stdout } = await execAsync(
      `python3 -c "${script.replace(/"/g, '\\"').replace(/\n/g, "\\n")}"`,
      { timeout: 30_000, input: urls.join("\n"), encoding: "utf8" } as any
    );
    const filtered = (stdout as unknown as string).toString().trim().split("\n").filter(Boolean);
    return filtered.length > 0 ? filtered : urls.slice(0, 200);
  } catch {
    return urls.slice(0, 200);
  }
}

// ── LinkFinder ────────────────────────────────────────────────────────────────

const LINKFINDER_PATH = "/tmp/security-tools/linkfinder.py";

async function runLinkfinder(url: string): Promise<string[]> {
  if (!fs.existsSync(LINKFINDER_PATH)) return [];
  try {
    const safeUrl = url.replace(/"/g, "").slice(0, 500);
    const { stdout } = await execAsync(
      `python3 "${LINKFINDER_PATH}" -i "${safeUrl}" -o cli 2>/dev/null`,
      { timeout: 30_000 }
    );
    return stdout.trim().split("\n")
      .filter(l => l.startsWith("/") || l.startsWith("http"))
      .slice(0, 200);
  } catch (err) {
    logger.warn({ url, err }, "LinkFinder failed");
    return [];
  }
}

// ── Main export ────────────────────────────────────────────────────────────────

export async function runParamScan(target: string, collectedUrls: string[] = []): Promise<ParamScanResult> {
  const empty: ParamScanResult = {
    discoveredParams: [], jsEndpoints: [], filteredUrls: [],
    stats: { urlsAnalyzed: 0, paramsFound: 0, jsEndpointsFound: 0, urlsFiltered: 0 },
  };

  let primaryUrl: string;
  try {
    const u = new URL(target.startsWith("http") ? target : `https://${target}`);
    primaryUrl = u.href;
  } catch { return empty; }

  // Select targets for arjun: primary URL + endpoints that look like APIs or have query params
  const interestingUrls = collectedUrls.filter(u =>
    u.includes("?") || u.includes("/api/") || u.includes("/search") || u.includes("/query")
  ).slice(0, 5);
  const arjunTargets = [primaryUrl, ...interestingUrls];

  // Find JS files for LinkFinder
  const jsFiles = collectedUrls.filter(u => u.endsWith(".js") || u.includes(".js?")).slice(0, 8);

  logger.info({ target, arjunTargets: arjunTargets.length, jsFiles: jsFiles.length }, "Param scan starting");

  const [arjunResults, jsEndpoints, filteredUrls] = await Promise.allSettled([
    Promise.allSettled(arjunTargets.map(u => runArjun(u)))
      .then(r => r.flatMap(x => x.status === "fulfilled" ? x.value : [])),
    Promise.allSettled(jsFiles.map(u => runLinkfinder(u)))
      .then(r => r.flatMap(x => x.status === "fulfilled" ? x.value : [])),
    collectedUrls.length > 20 ? runUro(collectedUrls) : Promise.resolve(collectedUrls),
  ]);

  const params = arjunResults.status === "fulfilled" ? arjunResults.value : [];
  const jsEps = [...new Set(jsEndpoints.status === "fulfilled" ? jsEndpoints.value : [])];
  const filtered = filteredUrls.status === "fulfilled" ? filteredUrls.value : collectedUrls;

  logger.info({ target, params: params.length, jsEndpoints: jsEps.length, filtered: filtered.length }, "Param scan complete");

  return {
    discoveredParams: params,
    jsEndpoints: jsEps.slice(0, 200),
    filteredUrls: filtered.slice(0, 500),
    stats: {
      urlsAnalyzed: arjunTargets.length,
      paramsFound: params.reduce((s, p) => s + p.params.length, 0),
      jsEndpointsFound: jsEps.length,
      urlsFiltered: filtered.length,
    },
  };
}
