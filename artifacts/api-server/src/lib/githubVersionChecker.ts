import { logger } from "./logger";

const GITHUB_API = "https://api.github.com";

function extractRepoPath(githubUrl: string): string | null {
  const match = githubUrl.match(/github\.com\/([^/]+\/[^/?#\s]+)/);
  return match ? match[1]!.replace(/\.git$/, "") : null;
}

function stripLeadingV(tag: string): string {
  return tag.replace(/^v/i, "").trim();
}

function buildHeaders(token?: string): Record<string, string> {
  const h: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "Sentinelware-CTEM/1.0",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  const tok = token ?? process.env["GITHUB_TOKEN"];
  if (tok) h["Authorization"] = `Bearer ${tok}`;
  return h;
}

/**
 * Fetch the latest release/tag version for a GitHub repo URL.
 * Returns the version string with any leading 'v' stripped (e.g. "1.2.3"),
 * or null if the repo has no releases/tags or the URL is not a GitHub URL.
 *
 * Pass githubToken to authenticate (5000 req/hr vs 60/hr unauthenticated).
 * If omitted, falls back to GITHUB_TOKEN env var automatically.
 */
export async function fetchLatestVersion(
  githubUrl: string,
  githubToken?: string,
): Promise<string | null> {
  const repo = extractRepoPath(githubUrl);
  if (!repo) return null;

  const headers = buildHeaders(githubToken);

  try {
    const relRes = await fetch(`${GITHUB_API}/repos/${repo}/releases/latest`, {
      headers,
      signal: AbortSignal.timeout(12_000),
    });

    if (relRes.ok) {
      const data = await relRes.json() as { tag_name?: string };
      if (data.tag_name) return stripLeadingV(data.tag_name);
    }

    // Some repos use tags only (no formal releases)
    const tagsRes = await fetch(`${GITHUB_API}/repos/${repo}/tags?per_page=1`, {
      headers,
      signal: AbortSignal.timeout(12_000),
    });
    if (tagsRes.ok) {
      const tags = await tagsRes.json() as { name: string }[];
      if (tags.length > 0) return stripLeadingV(tags[0]!.name);
    }

    // Log rate limit info when unauthenticated to help diagnose quota issues
    if (!headers["Authorization"]) {
      const remaining = relRes.headers.get("x-ratelimit-remaining");
      const reset = relRes.headers.get("x-ratelimit-reset");
      if (remaining !== null && Number(remaining) === 0) {
        const resetAt = reset ? new Date(Number(reset) * 1000).toISOString() : "unknown";
        logger.warn({ repo, resetAt }, "GitHub API rate limit exhausted — set GITHUB_TOKEN for 5000 req/hr");
      }
    }

    return null;
  } catch (err: any) {
    logger.warn({ repo, err: err?.message }, "GitHub version check failed");
    return null;
  }
}

/**
 * Try to detect the installed version of a binary by running it with
 * common version flags (--version, -version, version, -V).
 * Returns the raw first line of output, or null if not found.
 */
export async function detectInstalledVersion(binaryName: string): Promise<string | null> {
  const { execFile } = await import("child_process");
  const { promisify } = await import("util");
  const execAsync = promisify(execFile);

  // Verify binary exists first
  try {
    const { execFileSync } = await import("child_process");
    execFileSync("which", [binaryName], { timeout: 2000 });
  } catch {
    return null; // not installed
  }

  for (const flag of ["--version", "-version", "version", "-V"]) {
    try {
      const { stdout, stderr } = await execAsync(binaryName, [flag], {
        timeout: 4000,
        env: { ...process.env, PATH: process.env["PATH"] ?? "/usr/local/bin:/usr/bin:/bin" },
      });
      const raw = (stdout || stderr).split("\n")[0]?.trim() ?? "";
      if (raw.length > 0) return raw.slice(0, 100);
    } catch (e: any) {
      const raw = ((e?.stderr ?? "") || (e?.stdout ?? "")).split("\n")[0]?.trim() ?? "";
      if (raw.length > 0) return raw.slice(0, 100);
    }
  }
  return null;
}
