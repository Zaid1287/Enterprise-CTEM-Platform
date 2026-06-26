import { logger } from "./logger";

const GITHUB_API = "https://api.github.com";

function extractRepoPath(githubUrl: string): string | null {
  const match = githubUrl.match(/github\.com\/([^/]+\/[^/?#\s]+)/);
  return match ? match[1]!.replace(/\.git$/, "") : null;
}

function stripLeadingV(tag: string): string {
  return tag.replace(/^v/i, "").trim();
}

/**
 * Fetch the latest release/tag version for a GitHub repo URL.
 * Returns the version string with any leading 'v' stripped (e.g. "1.2.3"),
 * or null if the repo has no releases/tags or the URL is not a GitHub URL.
 */
export async function fetchLatestVersion(githubUrl: string): Promise<string | null> {
  const repo = extractRepoPath(githubUrl);
  if (!repo) return null;

  try {
    const relRes = await fetch(`${GITHUB_API}/repos/${repo}/releases/latest`, {
      headers: { Accept: "application/vnd.github+json", "User-Agent": "Sentinelware-CTEM/1.0" },
      signal: AbortSignal.timeout(10_000),
    });
    if (relRes.ok) {
      const data = await relRes.json() as { tag_name?: string };
      if (data.tag_name) return stripLeadingV(data.tag_name);
    }

    const tagsRes = await fetch(`${GITHUB_API}/repos/${repo}/tags?per_page=1`, {
      headers: { Accept: "application/vnd.github+json", "User-Agent": "Sentinelware-CTEM/1.0" },
      signal: AbortSignal.timeout(10_000),
    });
    if (tagsRes.ok) {
      const tags = await tagsRes.json() as { name: string }[];
      if (tags.length > 0) return stripLeadingV(tags[0]!.name);
    }

    return null;
  } catch (err: any) {
    logger.warn({ repo, err: err?.message }, "GitHub version check failed");
    return null;
  }
}
