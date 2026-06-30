export interface RiskFactor {
  label: string;
  points: number;
}

export interface EnrichmentInput {
  authStatus: "none" | "required" | "unknown";
  tools: Array<{ name: string; [k: string]: unknown }>;
  models: string[];
  corsPolicy: string | null;
  hasTls: boolean;
  systemPromptLeaked: boolean;
  signupEnabled: boolean;
}

const CRITICAL_TOOLS = ["exec_code","run_shell","execute","shell","bash","cmd","eval","subprocess","exec"];
const HIGH_TOOLS     = ["query_db","file_read","read_file","db_query","sql","filesystem","write_file","delete_file"];
const UNCENSORED_PATTERNS = ["uncensored","abliterated","nolimits","jailbreak","godmode"];

export function computeRiskScore(e: EnrichmentInput): { score: number; level: string; factors: RiskFactor[] } {
  const factors: RiskFactor[] = [];
  let score = 0;

  function add(label: string, pts: number) {
    if (pts > 0) { factors.push({ label, points: pts }); score += pts; }
  }

  if (e.authStatus === "none")    add("No authentication", 4.0);
  if (e.authStatus === "unknown") add("Unknown auth status", 1.0);

  if (e.tools.length >= 10) add("10+ tools exposed", 2.0);
  else if (e.tools.length >= 5) add("5+ tools exposed", 1.0);

  const toolNames = e.tools.map(t => (t.name as string ?? "").toLowerCase());
  toolNames.forEach(n => {
    if (CRITICAL_TOOLS.some(c => n.includes(c))) add(`Critical tool: ${n}`, 1.0);
  });
  toolNames.forEach(n => {
    if (HIGH_TOOLS.some(h => n.includes(h))) add(`High-risk tool: ${n}`, 0.5);
  });

  if (e.corsPolicy === "open") add("Open CORS policy", 1.0);
  if (!e.hasTls)               add("No TLS encryption", 0.5);
  if (e.systemPromptLeaked)    add("System prompt leaked", 0.5);
  if (e.models.length > 0)     add("Models exposed", 1.0);

  if (e.models.some(m => UNCENSORED_PATTERNS.some(p => m.toLowerCase().includes(p)))) {
    add("Uncensored model detected", 2.0);
  }

  if (e.signupEnabled) add("Open signup enabled", 1.5);

  if (e.authStatus === "none" && toolNames.some(n => CRITICAL_TOOLS.some(c => n.includes(c)))) {
    add("Dangerous combo: no-auth + critical tool", 1.0);
  }
  if (e.authStatus === "none" && e.corsPolicy === "open") {
    add("Dangerous combo: no-auth + open CORS", 1.0);
  }
  if (e.authStatus === "none" && e.models.length > 0) {
    add("Dangerous combo: no-auth + models exposed", 1.0);
  }

  score = Math.min(10, Math.round(score * 10) / 10);

  let level = "low";
  if (score >= 9) level = "critical";
  else if (score >= 7) level = "high";
  else if (score >= 4) level = "medium";

  return { score, level, factors };
}
