/**
 * OAuth Scope Risk Scoring
 * Maps OAuth/OIDC/delegated permission scopes to risk levels.
 * Risk model: readonly=low, files.readwrite=medium, admin.*=critical
 */

export type ScopeRiskLevel = "low" | "medium" | "high" | "critical";

interface ScopeRiskEntry {
  pattern: RegExp | string;
  level: ScopeRiskLevel;
  reason: string;
}

// Ordered highest → lowest — first match wins
const SCOPE_RULES: ScopeRiskEntry[] = [
  // ── CRITICAL (admin, directory, full access) ─────────────────────────────
  { pattern: /admin\.directory/i,                     level: "critical", reason: "Full directory admin access" },
  { pattern: /admin\.reports/i,                       level: "critical", reason: "Org-wide audit reports" },
  { pattern: /admin\.datatransfer/i,                  level: "critical", reason: "Data transfer between users" },
  { pattern: /admin\.reseller/i,                      level: "critical", reason: "Reseller admin access" },
  { pattern: /apps\.groups\.settings/i,               level: "critical", reason: "Google Groups settings" },
  { pattern: /User\.ReadWrite\.All/i,                 level: "critical", reason: "Read/write all users" },
  { pattern: /Directory\.ReadWrite\.All/i,            level: "critical", reason: "Full directory read/write" },
  { pattern: /RoleManagement\.ReadWrite\.Directory/i, level: "critical", reason: "Manage Azure AD roles" },
  { pattern: /Application\.ReadWrite\.All/i,          level: "critical", reason: "Read/write all applications" },
  { pattern: /AppRoleAssignment\.ReadWrite\.All/i,    level: "critical", reason: "Assign app roles to all users" },
  { pattern: /policy\.readwrite/i,                    level: "critical", reason: "Modify org policies" },
  { pattern: /SecurityEvents\.ReadWrite\.All/i,       level: "critical", reason: "Security event write access" },
  { pattern: /okta\.users\.manage/i,                  level: "critical", reason: "Manage all Okta users" },
  { pattern: /okta\.apps\.manage/i,                   level: "critical", reason: "Manage all Okta apps" },
  { pattern: /okta\.groups\.manage/i,                 level: "critical", reason: "Manage all Okta groups" },
  { pattern: /admin:org/i,                            level: "critical", reason: "GitHub org admin" },
  { pattern: /admin:enterprise/i,                     level: "critical", reason: "GitHub enterprise admin" },
  { pattern: /site_admin/i,                           level: "critical", reason: "Site admin access" },

  // ── HIGH (write to cloud files, email, calendars, contacts) ──────────────
  { pattern: /https:\/\/www\.googleapis\.com\/auth\/drive$/i,    level: "high", reason: "Full Google Drive access" },
  { pattern: /https:\/\/www\.googleapis\.com\/auth\/gmail\.modify/i, level: "high", reason: "Read/write Gmail" },
  { pattern: /https:\/\/www\.googleapis\.com\/auth\/gmail\.compose/i, level: "high", reason: "Send email as user" },
  { pattern: /https:\/\/www\.googleapis\.com\/auth\/contacts$/i, level: "high", reason: "Full contacts access" },
  { pattern: /drive(?!\.readonly|\.file|\.appdata|\.metadata)/i,  level: "high", reason: "Google Drive write access" },
  { pattern: /gmail\.(?:modify|send|compose|insert)/i,            level: "high", reason: "Gmail write access" },
  { pattern: /Files\.ReadWrite\.All/i,                             level: "high", reason: "Read/write all SharePoint files" },
  { pattern: /Mail\.ReadWrite/i,                                   level: "high", reason: "Read/write all mail" },
  { pattern: /Mail\.Send/i,                                        level: "high", reason: "Send email as user" },
  { pattern: /Contacts\.ReadWrite/i,                               level: "high", reason: "Read/write user contacts" },
  { pattern: /Calendars\.ReadWrite/i,                              level: "high", reason: "Read/write user calendars" },
  { pattern: /ChannelMessage\.Send/i,                              level: "high", reason: "Send Teams messages" },
  { pattern: /Chat\.ReadWrite/i,                                   level: "high", reason: "Read/write Teams chats" },
  { pattern: /repo$/i,                                             level: "high", reason: "Full GitHub repo access" },
  { pattern: /write:packages/i,                                    level: "high", reason: "GitHub package write" },
  { pattern: /delete_repo/i,                                       level: "high", reason: "GitHub repo delete" },

  // ── MEDIUM (read cloud files, calendar data, user profile beyond basics) ──
  { pattern: /drive\.readonly/i,                      level: "medium", reason: "Read all Drive files" },
  { pattern: /drive\.file/i,                          level: "medium", reason: "Access files created by app" },
  { pattern: /drive\.metadata/i,                      level: "medium", reason: "Read Drive metadata" },
  { pattern: /drive\.appdata/i,                       level: "medium", reason: "Access app-specific Drive folder" },
  { pattern: /gmail\.readonly/i,                      level: "medium", reason: "Read all Gmail messages" },
  { pattern: /gmail\.labels/i,                        level: "medium", reason: "Read Gmail labels" },
  { pattern: /gmail\.metadata/i,                      level: "medium", reason: "Read email metadata" },
  { pattern: /Files\.Read\.All/i,                     level: "medium", reason: "Read all SharePoint files" },
  { pattern: /Mail\.Read$/i,                          level: "medium", reason: "Read all mail" },
  { pattern: /Calendars\.Read/i,                      level: "medium", reason: "Read user calendars" },
  { pattern: /Contacts\.Read/i,                       level: "medium", reason: "Read user contacts" },
  { pattern: /People\.Read\.All/i,                    level: "medium", reason: "Read org directory" },
  { pattern: /User\.Read\.All/i,                      level: "medium", reason: "Read all users in org" },
  { pattern: /Group\.Read\.All/i,                     level: "medium", reason: "Read all groups" },
  { pattern: /ChannelMessage\.Read\.All/i,            level: "medium", reason: "Read all Teams messages" },
  { pattern: /Channel\.ReadBasic\.All/i,              level: "medium", reason: "Read Teams channel info" },
  { pattern: /okta\.users\.read/i,                    level: "medium", reason: "Read Okta users" },
  { pattern: /okta\.apps\.read/i,                     level: "medium", reason: "Read Okta apps" },
  { pattern: /read:org/i,                             level: "medium", reason: "Read GitHub org data" },
  { pattern: /read:user/i,                            level: "medium", reason: "Read all GitHub profile data" },
  { pattern: /repo:status/i,                          level: "medium", reason: "GitHub repo status access" },

  // ── LOW (basic profile, email address, sign-in only) ─────────────────────
  { pattern: /openid/i,               level: "low", reason: "OpenID Connect sign-in" },
  { pattern: /profile$/i,             level: "low", reason: "Basic profile info" },
  { pattern: /email$/i,               level: "low", reason: "User email address" },
  { pattern: /offline_access/i,       level: "low", reason: "Refresh tokens (offline access)" },
  { pattern: /userinfo\.email/i,      level: "low", reason: "Read email address" },
  { pattern: /userinfo\.profile/i,    level: "low", reason: "Read basic profile" },
  { pattern: /User\.Read$/i,          level: "low", reason: "Sign-in and read user profile" },
  { pattern: /user\.email/i,          level: "low", reason: "Read user email" },
  { pattern: /user\.profile/i,        level: "low", reason: "Read user profile" },
];

/**
 * Score a single scope string → { level, reason }
 */
export function scoreSingleScope(scope: string): { level: ScopeRiskLevel; reason: string } {
  for (const rule of SCOPE_RULES) {
    const match = typeof rule.pattern === "string"
      ? scope.toLowerCase() === rule.pattern.toLowerCase()
      : rule.pattern.test(scope);
    if (match) return { level: rule.level, reason: rule.reason };
  }
  // Unknown scope — treat as medium
  return { level: "medium", reason: "Unknown scope" };
}

const LEVEL_NUM: Record<ScopeRiskLevel, number> = { low: 1, medium: 2, high: 3, critical: 4 };

/**
 * Score an array of scopes → highest risk level + all matched rules
 */
export function scoreScopes(scopes: string[]): {
  level: ScopeRiskLevel;
  score: number;
  breakdown: Array<{ scope: string; level: ScopeRiskLevel; reason: string }>;
} {
  if (!scopes || scopes.length === 0) return { level: "low", score: 10, breakdown: [] };

  const breakdown = scopes.map(s => ({ scope: s, ...scoreSingleScope(s) }));
  let maxNum = 0;
  for (const b of breakdown) {
    if (LEVEL_NUM[b.level] > maxNum) maxNum = LEVEL_NUM[b.level];
  }

  const level: ScopeRiskLevel = (["low", "medium", "high", "critical"] as ScopeRiskLevel[])[maxNum - 1] ?? "low";
  const scoreMap: Record<ScopeRiskLevel, number> = { low: 15, medium: 40, high: 65, critical: 90 };

  return { level, score: scoreMap[level], breakdown };
}

/**
 * Human-readable permission summary groups
 */
export function buildPermissionSummary(scopes: string[]): {
  canReadFiles: boolean;
  canWriteFiles: boolean;
  canReadEmail: boolean;
  canSendEmail: boolean;
  canReadCalendar: boolean;
  canManageUsers: boolean;
  hasAdminAccess: boolean;
  scopeCount: number;
  highestRisk: ScopeRiskLevel;
} {
  const s = scopes.join(" ");
  const { level } = scoreScopes(scopes);
  return {
    canReadFiles: /drive\.readonly|Files\.Read|drive\.metadata|drive\.file/i.test(s),
    canWriteFiles: /drive(?!\.readonly)|Files\.ReadWrite|drive\.readwrite/i.test(s),
    canReadEmail: /gmail\.readonly|gmail\.metadata|Mail\.Read/i.test(s),
    canSendEmail: /gmail\.compose|gmail\.send|Mail\.Send/i.test(s),
    canReadCalendar: /calendar|Calendars\.Read/i.test(s),
    canManageUsers: /User\.ReadWrite|admin\.directory\.user|okta\.users\.manage/i.test(s),
    hasAdminAccess: level === "critical",
    scopeCount: scopes.length,
    highestRisk: level,
  };
}
