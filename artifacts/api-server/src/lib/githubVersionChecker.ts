import { logger } from "./logger";

const GITHUB_API = "https://api.github.com";

function extractRepoPath(githubUrl: string): string | null {
  const match = githubUrl.match(/github\.com\/([^/]+\/[^/?#\s]+)/);
  return match ? match[1]!.replace(/\.git$/, "") : null;
}

export interface VersionCheckResult {
  latestVersion: string | null;
  error?: string;
}

export async function fetchLatestVersion(githubUrl: string): Promise<VersionCheckResult> {
  const repo = extractRepoPath(githubUrl);
  if (!repo) return { latestVersion: null, error: "Not a GitHub URL" };

  try {
    const relRes = await fetch(`${GITHUB_API}/repos/${repo}/releases/latest`, {
      headers: { Accept: "application/vnd.github+json", "User-Agent": "Sentinelware-CTEM/1.0" },
      signal: AbortSignal.timeout(10_000),
    });
    if (relRes.ok) {
      const data = await relRes.json() as { tag_name?: string };
      if (data.tag_name) return { latestVersion: data.tag_name };
    }

    const tagsRes = await fetch(`${GITHUB_API}/repos/${repo}/tags?per_page=1`, {
      headers: { Accept: "application/vnd.github+json", "User-Agent": "Sentinelware-CTEM/1.0" },
      signal: AbortSignal.timeout(10_000),
    });
    if (tagsRes.ok) {
      const tags = await tagsRes.json() as { name: string }[];
      if (tags.length > 0) return { latestVersion: tags[0]!.name };
    }

    return { latestVersion: null, error: "No releases or tags found" };
  } catch (err: any) {
    logger.warn({ repo, err: err?.message }, "GitHub version check failed");
    return { latestVersion: null, error: String(err?.message ?? err) };
  }
}
