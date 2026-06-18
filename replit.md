# Sentinelware — Enterprise CTEM Platform

Enterprise-grade multi-tenant Continuous Threat Exposure Management (CTEM) platform. Combines External Attack Surface Management (EASM), Cyber Asset Attack Surface Management (CAASM), Vulnerability Management, Exposure Management, Compliance Management, Risk Prioritization, and an AI Security Copilot into a single SaaS product.

---

## Quick Start — Run & Operate

```bash
# Start both services (normally done via Replit workflows — see below)
pnpm --filter @workspace/api-server run dev       # API server
pnpm --filter @workspace/ctem-platform run dev    # Frontend

# Type-check everything
pnpm run typecheck

# After any OpenAPI spec change — regenerate hooks + Zod schemas
pnpm --filter @workspace/api-spec run codegen

# Push DB schema changes (dev only — never against prod without backup)
pnpm --filter @workspace/db run push
```

### Workflows (Replit-managed)

| Workflow | Command | Port | Proxy Path |
|---|---|---|---|
| `artifacts/api-server: API Server` | `pnpm --filter @workspace/api-server run dev` | 8080 | `/api` |
| `artifacts/ctem-platform: web` | `pnpm --filter @workspace/ctem-platform run dev` | 23203 | `/` |
| `artifacts/mockup-sandbox: Component Preview Server` | `pnpm --filter @workspace/mockup-sandbox run dev` | — | `/mockup-sandbox` |

### Required Environment Variables

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string (Replit-managed) |
| `SESSION_SECRET` | JWT signing secret (Replit secret) |

### Optional Environment Variables (configure in Platform Settings UI or Replit Secrets)

| Variable | Purpose |
|---|---|
| `OPENAI_API_KEY` | AI Copilot — GPT-4o-mini inference |
| `RESEND_API_KEY` | Email alerts via Resend |
| `STRIPE_SECRET_KEY` | Billing & subscriptions |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signature verification |
| `REDIS_URL` | BullMQ job queue (optional — falls back to in-process queue) |

---

## Tech Stack

### Frontend

| Technology | Version | Role |
|---|---|---|
| React | 19 | UI framework |
| Vite | Latest | Build tool + dev server |
| TypeScript | 5.9 | Type safety |
| Tailwind CSS | v4 | Styling |
| ShadCN UI | Latest | Component library |
| TanStack Query | v5 | Server state, caching, mutations |
| Zustand | v5 | Auth state (access token, user, role) |
| Wouter | v3 | Client-side routing |
| Recharts | v2 | Charts (risk trends, severity breakdown) |
| D3 | v7 | Attack surface force-directed graph |
| Orval (codegen) | Latest | Generates React Query hooks from OpenAPI |

### Backend

| Technology | Version | Role |
|---|---|---|
| Node.js | 24 | Runtime |
| Express | 5 | HTTP server |
| TypeScript | 5.9 | Type safety |
| Drizzle ORM | Latest | Database queries |
| drizzle-zod | Latest | Schema → Zod validation |
| Zod | v3 | Input/output validation |
| esbuild | Latest | Bundle API server to single ESM file |
| BullMQ | Latest | Job queue (when Redis available) |
| Puppeteer | Latest | Headless screenshot engine |
| Nodemailer / Resend | Latest | Email dispatch |

### Database & Infrastructure

| Technology | Role |
|---|---|
| PostgreSQL | Primary database (Replit-managed) |
| Drizzle ORM | Schema, migrations, query builder |
| Row Level Security | Tenant isolation at DB level |
| PostgreSQL tsvector | Full-text search (no OpenSearch) |
| Redis (optional) | BullMQ broker; in-memory queue when absent |

### Stack Deviations from Original Spec

The original requirements specified Next.js 15, FastAPI, Python 3.12, SQLAlchemy, Redis (required), MinIO, Celery, Docker, and Kubernetes. The Replit environment required a different stack:

| Spec | Built | Why |
|---|---|---|
| Next.js 15 | React 19 + Vite | Replit SPA pattern |
| FastAPI + Python | Express 5 + Node.js/TypeScript | Replit environment |
| SQLAlchemy + Alembic | Drizzle ORM + `db push` | Node.js ecosystem |
| OpenSearch | PostgreSQL tsvector | No OpenSearch in Replit |
| Redis (required) | Redis optional, in-memory fallback | Replit env |
| Celery + Celery Beat | BullMQ + beatScheduler.ts | Node.js equivalent |
| MinIO | Base64 in PostgreSQL | No object storage in Replit |
| Docker + Compose | Replit workflows | Replit environment |
| React Hook Form | Standard React controlled inputs | Simpler for this use case |
| Gowitness | Puppeteer | Same output; easier to install |

---

## Monorepo Structure

```
/
├── artifacts/
│   ├── api-server/                  # Express 5 API — the backend
│   │   └── src/
│   │       ├── app.ts               # Express app setup, middleware stack
│   │       ├── index.ts             # Entry point — starts server, init workers
│   │       ├── routes/              # One file per module (see Routes section)
│   │       ├── lib/                 # Shared utilities and engines
│   │       └── workers/             # Background workers (beat, scan, alert)
│   ├── ctem-platform/               # React + Vite frontend
│   │   └── src/
│   │       ├── App.tsx              # All routes registered here
│   │       ├── pages/               # One file per page/module
│   │       └── components/
│   │           ├── layout/          # Sidebar, Navbar, AppLayout
│   │           └── ui/              # ShadCN component wrappers
│   └── mockup-sandbox/              # Canvas component preview server
├── lib/
│   ├── api-spec/
│   │   └── openapi.yaml             # SOURCE OF TRUTH for all API contracts
│   ├── api-client-react/
│   │   └── src/generated/api.ts     # Generated React Query hooks (do not edit)
│   ├── api-zod/
│   │   └── src/generated/api.ts     # Generated Zod schemas (do not edit)
│   └── db/
│       └── src/schema/              # Drizzle table definitions (see Schema section)
├── scripts/                         # Utility scripts
├── pnpm-workspace.yaml              # Workspace config, catalog pins, overrides
├── tsconfig.json                    # Root TS solution file (libs only)
└── tsconfig.base.json               # Shared strict TS defaults
```

---

## Full Architecture

### Request Flow

```
Browser
  │
  ▼
Replit Proxy (localhost:80)
  │
  ├── /api/*  ──────────────────────────► Express 5 API Server (port 8080)
  │                                           │
  │                                           ├── Helmet (secure headers)
  │                                           ├── CORS
  │                                           ├── express.json()
  │                                           ├── Auth rate limiter (20/15min on /api/auth/*)
  │                                           ├── Global rate limiter (200/15min on /api/*)
  │                                           ├── requireAuth middleware (JWT validation)
  │                                           ├── Route handlers (routes/)
  │                                           │     └── tenantId scoped to JWT
  │                                           └── PostgreSQL (Drizzle ORM)
  │
  └── /*  ──────────────────────────────► React + Vite Frontend (port 23203)
                                              │
                                              ├── Wouter router
                                              ├── TanStack Query (server state)
                                              ├── Zustand (auth state)
                                              └── Orval-generated hooks → /api/*
```

### Authentication Flow

```
POST /api/auth/login
  │
  ▼
Validate credentials → bcrypt compare
  │
  ▼
Issue JWT access token (15 min) + refresh token (7 days, stored in DB)
  │
  ▼
Client stores access token in sessionStorage
  │
  ▼
Every API request: Authorization: Bearer <token>
  │
  ▼
requireAuth middleware → verifies JWT → extracts { userId, tenantId, role }
  │
  ▼
All DB queries: WHERE tenant_id = req.user.tenantId
```

### Scan Pipeline Architecture

```
Trigger (manual / beatScheduler / schedule)
  │
  ▼
enqueueAndRun(assetId, scanId, tenantId)
  │
  ├── Check: asset verified? (verificationStatus = 'verified')
  ├── Check: scan not already running? (duplicate prevention)
  │
  ▼
PHASE 1 (parallel):
  ├── Passive Discovery (WHOIS, DNS, SPF/DMARC/DKIM, crt.sh, ASN)
  ├── Subdomain Enumeration (subfinder, dnsx, shuffledns)
  └── Shodan / VirusTotal enrichment

PHASE 2 (parallel):
  ├── Port Scanning (Nmap → Naabu → Masscan fallback chain)
  ├── SSL/TLS Analysis (tls.connect, certificate parsing)
  └── HTTP Probing (httpx-style: status, title, headers)

PHASE 3 (parallel):
  ├── Technology Detection (400+ signature rules via techDetector.ts)
  ├── Screenshot Capture (Puppeteer — homepage, login pages, admin panels)
  └── Directory Fuzzing (BFS depth-3, 2000 endpoint limit)

PHASE 4 (parallel):
  ├── Nuclei Scanning (40+ templates: CVEs, exposed panels, secrets, misconfigs)
  ├── Secrets Hunting (trufflehog-style pattern matching, .git exposure)
  ├── JavaScript Analysis (jsAnalyzer.ts — API keys, secrets in JS files)
  ├── Cloud Recon (S3/GCS/Azure bucket permutation enumeration)
  └── Parameter Discovery (active fuzzing for injectable params)

PHASE 5 (sequential):
  ├── Exposed Port Findings (26 dangerous ports → critical findings)
  ├── EPSS enrichment (first.org batch API — 100 CVEs/request)
  ├── KEV enrichment (CISA catalog — 24h cache)
  ├── Deduplication (matching by cveId + assetId)
  ├── Finding INSERT to DB
  └── finalizeScannedAssets() → update lastScannedAt, risk scores

Result Processor:
  ├── Risk score recalculation (CVSS + EPSS + KEV + criticality + exposure + businessImpact)
  └── dispatchNotifications() → alert rules → channels (Email/Slack/Discord/Telegram/Webhook)
```

### Background Worker Architecture

```
index.ts (startup)
  │
  ├── initBeatScheduler()      ← beatScheduler.ts
  │     ├── Every 60s: dispatchDueSchedules()
  │     │     └── SELECT scan_schedules WHERE nextRunAt <= NOW()
  │     │           └── enqueueOrRun(assetId) → pipelineScans
  │     └── Every 60s: asset-frequency dispatch
  │           └── SELECT assets WHERE nextScanAt <= NOW()
  │                 └── enqueueOrRun(assetId)
  │
  ├── initScanWorker()         ← scanWorker.ts (BullMQ when Redis available)
  │     └── Processes scan jobs from queue (MAX_CONCURRENT_SCANS=5)
  │
  └── initAlertWorker()        ← alertWorker.ts
        └── Processes notification jobs from queue
```

### Multi-Tenant Isolation

```
JWT payload: { userId, tenantId, role, email }
      │
      ▼
Every DB query adds:
  WHERE tenant_id = req.user.tenantId

PostgreSQL RLS (also enforced at DB level):
  CREATE POLICY tenant_isolation ON <table>
    USING (tenant_id = current_setting('app.tenant_id')::int)

Immutable audit log:
  PostgreSQL trigger: BEFORE UPDATE OR DELETE ON audit_logs → RAISE EXCEPTION
```

---

## API Routes

All routes are under `/api`. No version prefix (deviation from spec).

### Auth (`auth.ts`)

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/auth/login` | Public | Login, returns access + refresh tokens |
| POST | `/auth/register` | Public | Register new tenant + admin user + seed data |
| POST | `/auth/refresh` | Public | Refresh access token |
| POST | `/auth/logout` | Auth | Revoke refresh token |
| GET | `/auth/me` | Auth | Current user profile |
| PATCH | `/auth/change-password` | Auth | Change password |
| POST | `/auth/forgot-password` | Public | Send password reset email |
| POST | `/auth/reset-password` | Public | Consume reset token |
| POST | `/auth/2fa/enable` | Auth | Request email OTP for 2FA setup |
| POST | `/auth/2fa/confirm` | Auth | Confirm OTP to activate 2FA |
| POST | `/auth/2fa/verify` | Auth | Verify OTP during login |
| POST | `/auth/2fa/disable` | Auth | Disable 2FA |
| POST | `/auth/avatar` | Auth | Upload avatar (multipart) |
| GET | `/auth/sessions` | Auth | List active sessions |
| DELETE | `/auth/sessions/:id` | Auth | Revoke a session |

### Assets (`assets.ts`)

| Method | Path | Description |
|---|---|---|
| GET | `/assets` | List assets (tenant-scoped; client sees only own) |
| POST | `/assets` | Create asset |
| GET | `/assets/:id` | Get asset detail |
| PATCH | `/assets/:id` | Update asset |
| DELETE | `/assets/:id` | Delete asset |
| POST | `/assets/:id/verify` | Initiate ownership verification |
| GET | `/assets/:id/verify/email-confirm` | Email verification callback |
| GET | `/assets/:id/technologies` | List detected technologies |

### Asset Groups (`assetGroups.ts`)

| Method | Path | Description |
|---|---|---|
| GET | `/asset-groups` | List groups |
| POST | `/asset-groups` | Create group |
| GET | `/asset-groups/:id` | Get group + members |
| PATCH | `/asset-groups/:id` | Update group |
| DELETE | `/asset-groups/:id` | Delete group |
| POST | `/asset-groups/:id/assets` | Add asset to group |
| DELETE | `/asset-groups/:id/assets/:assetId` | Remove asset from group |

### Scans (`scans.ts` + `pipelineScans.ts`)

| Method | Path | Description |
|---|---|---|
| GET | `/scans` | List scans |
| POST | `/scans` | Create and start scan |
| GET | `/scans/:id` | Get scan detail |
| DELETE | `/scans/:id` | Cancel running scan |
| GET | `/scans/:id/jobs` | List scan jobs |
| GET | `/scans/pipeline/tools` | Available pipeline tools |
| POST | `/pipeline-run` | Trigger pipeline scan for asset |

### Scan Schedules (`scans.ts`)

| Method | Path | Description |
|---|---|---|
| GET | `/scan-schedules` | List schedules |
| POST | `/scan-schedules` | Create schedule |
| PATCH | `/scan-schedules/:id` | Update schedule |
| DELETE | `/scan-schedules/:id` | Delete schedule |

### Findings (`findings.ts`)

| Method | Path | Description |
|---|---|---|
| GET | `/findings` | List findings (filterable by severity, status, asset) |
| GET | `/findings/:id` | Get finding detail |
| PATCH | `/findings/:id` | Update finding status |
| DELETE | `/findings/:id` | Delete finding |
| GET | `/findings/:id/comments` | List comments |
| POST | `/findings/:id/comments` | Add comment |
| DELETE | `/findings/:id/comments/:cid` | Delete comment |
| GET | `/findings/:id/scan-data` | Get raw scan data for finding |

### Discovery (`discovery.ts`)

| Method | Path | Description |
|---|---|---|
| POST | `/discovery/run/:assetId` | Trigger passive discovery |
| GET | `/discovery/results/:assetId` | List discovery results |
| GET | `/discovery/latest/:assetId` | Latest discovery result |

### Compliance (`compliance.ts`)

| Method | Path | Description |
|---|---|---|
| GET | `/compliance/frameworks` | List frameworks (ISO 27001, SOC2, PCI DSS, HIPAA, CIS) |
| GET | `/compliance/controls` | List controls |
| POST | `/compliance/controls` | Create control |
| PATCH | `/compliance/controls/:id` | Update control |
| DELETE | `/compliance/controls/:id` | Delete control |
| POST | `/compliance/controls/:id/evidence` | Upload evidence file |
| GET | `/compliance/controls/:id/evidence/:filename` | Download evidence file |
| DELETE | `/compliance/controls/:id/evidence/:filename` | Delete evidence file |
| GET | `/compliance/summary` | Gap analysis summary per framework |

### Risk (`risk.ts`)

| Method | Path | Description |
|---|---|---|
| GET | `/risk/scores` | List risk scores for all assets |
| GET | `/risk/scores/:assetId` | Risk score + history for asset |
| POST | `/risk/recalculate` | Force risk recalculation |

### Alerts (`alerts.ts`)

| Method | Path | Description |
|---|---|---|
| GET | `/alerts` | List alerts |
| GET | `/alerts/:id` | Alert detail |
| PATCH | `/alerts/:id` | Acknowledge / dismiss |
| GET | `/alert-rules` | List alert rules |
| POST | `/alert-rules` | Create alert rule |
| PATCH | `/alert-rules/:id` | Update alert rule |
| DELETE | `/alert-rules/:id` | Delete alert rule |
| GET | `/alerts/stream` | SSE stream — real-time alert push |

### Reports (`reports.ts`)

| Method | Path | Description |
|---|---|---|
| GET | `/reports` | List reports |
| POST | `/reports` | Create report |
| GET | `/reports/:id` | Get report |
| DELETE | `/reports/:id` | Delete report |
| GET | `/reports/:id/download` | Download report (CSV/JSON) |
| GET | `/reports/pdf-data/asset/:assetId` | PDF data for single asset |
| GET | `/reports/pdf-data/brand-threat/:scanId` | PDF data for brand threat scan |
| GET | `/reports/pdf-data/report/:reportId` | PDF data for full report |
| GET | `/reports/:id/download?format=csv` | CSV export |
| GET | `/reports/:id/download?format=json` | JSON export |

### AI Copilot (`ai.ts`)

| Method | Path | Description |
|---|---|---|
| POST | `/ai/explain-finding` | Explain a finding + CVE + risk |
| POST | `/ai/remediation` | Remediation guidance for a finding |
| POST | `/ai/executive-summary` | Executive summary for report |
| POST | `/ai/compliance-guidance` | Guidance for compliance control |
| GET | `/ai/status` | LLM availability check |

### Security Tools (`tools.ts`)

| Method | Path | Description |
|---|---|---|
| GET | `/tools` | List all available tools |
| POST | `/tools` | Add tool |
| GET | `/tools/pipeline` | Get pipeline tool config |
| POST | `/tools/pipeline` | Save pipeline config |
| POST | `/tools/run` | Run a tool (real exec) |
| GET | `/tool-runs` | List tool run history |
| GET | `/tool-runs/:id` | Get tool run detail |

### Brand Threats (`brandThreats.ts`)

| Method | Path | Description |
|---|---|---|
| GET | `/brand-threats` | List brand threat scans |
| POST | `/brand-threats` | Start brand threat scan |
| GET | `/brand-threats/:id` | Get scan detail + results |
| DELETE | `/brand-threats/:id` | Delete scan |

### Takedowns (`takedowns.ts`)

| Method | Path | Description |
|---|---|---|
| GET | `/takedowns` | List takedown requests |
| POST | `/takedowns` | Create takedown request |
| PATCH | `/takedowns/:id` | Update status |
| DELETE | `/takedowns/:id` | Delete request |

### Users & Tenants

| Method | Path | Description |
|---|---|---|
| GET | `/users` | List users (admin only) |
| POST | `/users` | Create user |
| PATCH | `/users/:id` | Update user |
| DELETE | `/users/:id` | Delete user |
| GET | `/tenants` | List tenants (super_admin only) |
| POST | `/tenants` | Create tenant (super_admin only) |
| GET | `/invitations` | List invitations |
| POST | `/invitations` | Send invitation |

### Other

| Method | Path | Description |
|---|---|---|
| GET | `/graph/attack-surface` | Attack surface graph (Neo4j-style nodes + relationships) |
| GET | `/dashboard/summary` | Dashboard metrics |
| GET | `/audit-logs` | Audit log entries |
| GET | `/search?q=` | Full-text search across assets/findings |
| GET | `/platform-settings` | Get platform settings |
| PATCH | `/platform-settings` | Update platform settings |
| GET | `/queues` | Queue monitor (super_admin) |
| GET | `/health` | Health check |
| GET | `/stripe/products` | Stripe products |
| POST | `/stripe/checkout` | Create checkout session |
| GET | `/stripe/subscription` | Current subscription |
| POST | `/stripe/portal` | Billing portal session |

---

## Database Schema

All tables include `tenantId integer NOT NULL` for multi-tenant isolation. PostgreSQL RLS policies enforce this at the database level.

### Core Tables

| Table | Key Columns | Notes |
|---|---|---|
| `tenants` | id, name, domain, plan, stripeCustomerId | One per organization |
| `users` | id, tenantId, email, passwordHash, role, twoFactorEnabled | role: super_admin/admin/manager/client |
| `sessions` | id, userId, tenantId, tokenHash, userAgent, ip, expiresAt | SHA256 of access token |
| `invitations` | id, tenantId, email, role, token, expiresAt | Pre-registration invites |

### Asset Tables

| Table | Key Columns | Notes |
|---|---|---|
| `assets` | id, tenantId, name, type, domain, ip, url, status, verificationStatus, riskLevel, businessImpact, tags, lastScannedAt | businessImpact: 1-10, default 5 |
| `asset_groups` | id, tenantId, name, description | |
| `asset_group_members` | groupId, assetId | Join table |
| `technology_detections` | id, tenantId, assetId, name, category, version, confidence, scanId | Per-scan tech fingerprints |
| `screenshots` | id, tenantId, assetId, scanId, url, data (base64), title, statusCode | Stored as base64 PNG |
| `discovery_results` | id, tenantId, assetId, source, data, createdAt | Historical passive discovery |

### Scan Tables

| Table | Key Columns | Notes |
|---|---|---|
| `scans` | id, tenantId, assetId, status, type, startedAt, completedAt | status: pending/running/completed/failed/cancelled |
| `scan_jobs` | id, scanId, assetId, tenantId, status, result | Per-asset job within a scan |
| `scan_asset_results` | id, scanId, assetId, tenantId, raw (jsonb) | Full raw scan output |
| `scan_schedules` | id, tenantId, assetId, frequency, nextRunAt, lastRunAt, isActive | frequency: hourly/daily/weekly/monthly |
| `security_tools` | id, tenantId, name, category, installCommand, runCommand | Tool registry |
| `tool_pipeline_steps` | id, tenantId, toolName, phase, isEnabled, order | Pipeline config per tenant |
| `tool_runs` | id, tenantId, toolName, assetId, scanId, status, output, exitCode | Tool execution history |

### Vulnerability Tables

| Table | Key Columns | Notes |
|---|---|---|
| `findings` | id, tenantId, assetId, scanId, title, severity, status, cveId, cvss, epss, cwe, isKev, description, remediation | status: open/in_progress/accepted_risk/false_positive/mitigated |
| `finding_comments` | id, findingId, tenantId, userId, text, createdAt | Threaded discussion |

### Compliance Tables

| Table | Key Columns | Notes |
|---|---|---|
| `compliance_frameworks` | id, tenantId, name, version | ISO 27001, SOC2, PCI DSS, HIPAA, CIS Controls |
| `compliance_controls` | id, tenantId, frameworkId, controlId, title, status, evidence, assignee, dueDate | evidence: JSON-encoded array of filenames |

### Risk Tables

| Table | Key Columns | Notes |
|---|---|---|
| `risk_scores` | id, tenantId, assetId, score, level, factors (jsonb), calculatedAt | Multi-factor: CVSS+EPSS+KEV+criticality+exposure+businessImpact |

### Alerting Tables

| Table | Key Columns | Notes |
|---|---|---|
| `alerts` | id, tenantId, title, severity, type, assetId, findingId, status, seenAt | |
| `alert_rules` | id, tenantId, name, triggerType, channel, channelConfig (jsonb), isActive | channelConfig holds webhook URL, Telegram chat ID, etc. |

### Reporting Tables

| Table | Key Columns | Notes |
|---|---|---|
| `reports` | id, tenantId, title, type, format, status, filePath, createdAt | type: executive/technical/compliance/inventory |

### Platform Tables

| Table | Key Columns | Notes |
|---|---|---|
| `audit_logs` | id, tenantId, userId, action, resourceType, resourceId, metadata, ip, createdAt | Immutable — DB trigger blocks UPDATE/DELETE |
| `platform_settings` | id, tenantId, key, value | key-value store for API keys, toggles |
| `user_ai_settings` | id, userId, tenantId, provider, apiKey, model, systemPrompt | Per-user LLM settings |

### Brand Threat Tables

| Table | Key Columns | Notes |
|---|---|---|
| `brand_threat_scans` | id, tenantId, brandName, status, permutationCount | |
| `brand_threat_results` | id, scanId, tenantId, domain, type, risk, registrar, registeredAt, screenshot | |
| `takedown_requests` | id, tenantId, domain, brandScanResultId, status, reason, notes | |

### Additional Tables

| Table | Key Columns | Notes |
|---|---|---|
| `packages` | id, name, price, features, maxAssets, maxUsers | Pricing tiers |
| `account_manager_clients` | managerId, clientId, tenantId | AM ↔ Client assignments |

---

## Frontend Pages

All pages are protected routes (redirect to `/login` if unauthenticated). Public routes: `/login`, `/register`, `/forgot-password`.

| Route | Page Component | Description |
|---|---|---|
| `/dashboard` | DashboardPage | Risk trends, severity chart, top vulnerable assets, recent alerts |
| `/assets` | AssetsPage | Asset inventory table, bulk actions, filters |
| `/assets/:id` | AssetDetailPage | Full asset detail — findings, tech, screenshots, risk, scan history |
| `/asset-groups` | AssetGroupsPage | Group management |
| `/asset-groups/:groupId` | AssetGroupDetailPage | Group members and group-level risk |
| `/topology` | AssetTopologyPage | D3 force-directed attack surface graph |
| `/findings` | FindingsPage | Vulnerability management — drawer with tabs (Details / Comments / Screenshots) |
| `/findings/:id` | FindingDetailPage | Individual finding detail |
| `/scans` | ScansPage | Scan management, live progress, schedule config |
| `/scan-reports` | ScanReportsPage | List of completed scan reports |
| `/scan-reports/:id` | ScanReportPage | Full scan report — all assets, findings, screenshots |
| `/discovery` | DiscoveryPage | Passive OSINT results per asset |
| `/exposure` | ExposurePage | Exposure analysis — dangerous ports, misconfigs |
| `/compliance` | CompliancePage | Framework scores, gap analysis, evidence upload/download |
| `/risk` | RiskPage | Risk scoring dashboard, asset risk breakdown |
| `/alerts` | AlertsPage | Alert inbox, alert rules, channel config |
| `/alerts/:id` | AlertDetailPage | Individual alert detail |
| `/ai-copilot` | AiCopilotPage | AI chat — explain findings, remediation, executive summaries |
| `/reports` | ReportsPage | Report generation, PDF/CSV/JSON download |
| `/audit-logs` | AuditLogsPage | Immutable audit trail |
| `/tools` | SecurityToolsPage | Tool library, pipeline config, tool run history |
| `/brand-threats` | BrandThreatPage | Brand threat scan management |
| `/brand-threats/:id` | BrandThreatDetailPage | Typosquatting results, domain risk, screenshots |
| `/takedowns` | TakedownsPage | Takedown request management |
| `/queue-monitor` | QueueMonitorPage | BullMQ queue metrics (super_admin) |
| `/settings/users` | UsersPage | User management |
| `/settings/tenant` | TenantSettingsPage | Tenant configuration |
| `/settings/platform` | PlatformSettingsPage | Platform-wide API keys and toggles |
| `/settings/account` | AccountSettingsPage | Profile, avatar, 2FA, sessions, AI settings |
| `/packages` | PackagesPage | Pricing tiers and subscription management |
| `/my-clients` | MyClientsPage | Account manager's client list |
| `/tenants` | TenantsPage | Tenant management (super_admin only) |

---

## Modules — Implementation Status

### Module 1: Asset Inventory — ✅ Complete

- All 10 asset types: Domain, Subdomain, URL, IP, CIDR, API, SSL Certificate, Cloud Asset, Host, Mobile Application
- Asset tags: Production, Staging, Development, Critical, Internal, External (free-text array)
- Business Impact field (1–10 integer, default 5) — factored into risk score
- Asset grouping with group detail pages
- Ownership verification: DNS TXT, Email, HTTP file (Cloud verification is basic)
- Asset topology visualization via D3 force-directed graph

### Module 2: Passive Discovery — ✅ Complete

Sources: CT logs (crt.sh), WHOIS, ASN (ip-api.com), DNS (A/AAAA/MX/NS/TXT/SOA/CNAME/SRV), SPF (full policy parse), DMARC (full policy parse including adkim/aspf/pct), DKIM selector probing, Certificate Transparency, GitHub Exposure (Search API), AlienVault OTX, Wayback Machine, URLScan.io, RapidDNS, CommonCrawl, Shodan InternetDB.

Reverse WHOIS: basic coverage only (no dedicated reverse WHOIS API service).

### Module 3: Active Discovery — ✅ Complete

Port scanners: Nmap (`-sT --top-ports 1000 -sV`), Naabu (auto-installs), Masscan (CAP_NET_RAW fallback), RustScan. Fallback chain used automatically based on tool availability.

Also: DNSX (DNS resolution), Httpx-style HTTP probing, TLS handshake analysis, SSL certificate parsing (expiry, issuer, SANs).

### Module 4: Technology Detection — ✅ Complete

400+ technology signatures in `techDetector.ts`. Version extraction from headers/HTML when available. Auto-stored to `technology_detections` table after each scan, replacing previous detections for that asset.

### Module 5: Screenshot Engine — ✅ Complete (with deviation)

- Engine: Puppeteer/Chromium (not Gowitness as specified)
- Captures: homepages, login pages, admin panels
- Storage: base64 PNG in PostgreSQL (not MinIO as specified)
- Displayed in asset detail, finding drawer screenshots tab, scan reports

### Module 6: Vulnerability Management — ✅ Complete

- Nuclei: custom implementation with 40+ templates (`nucleiScanner.ts`) covering exposed panels, sensitive files, CVE patterns, misconfigurations
- EPSS: batch enrichment via first.org API (100 CVEs/batch)
- KEV: CISA Known Exploited Vulnerabilities catalog with 24h cache
- Finding statuses: Open, In Progress, Accepted Risk, False Positive, Mitigated
- Finding comments: threaded, per-finding
- Evidence on findings: comments only — file evidence uploads exist only on compliance controls

### Module 7: Exposure Management — ✅ Complete

26 dangerous ports detected with auto-generated findings: FTP(21), Telnet(23), NetBIOS(139), SNMP(161), LDAP(389), SMB(445), RDP(3389), MSSQL(1433), Oracle(1521), MySQL(3306), MongoDB(27017), Redis(6379), Elasticsearch(9200/9300), Docker API(4243), etcd(2379), and more. Also: Jenkins, Grafana, Kibana, admin panels via Nuclei templates; S3/GCS/Azure bucket enumeration via cloud recon.

### Module 8: Internal Go Agent — ❌ Not Built

The entire Go agent system (Windows/Linux/macOS binary, agent registration, host data collection, patch info) was not implemented. This was the most complex infrastructure piece and would require a separate artifact.

### Module 9: Scan Orchestration — ✅ Complete (custom cron pending)

Full pipeline: Asset → beatScheduler → enqueueAndRun → pipelineScans → Result Processor → DB. Scan frequencies: hourly, daily, weekly, monthly. Custom cron expressions not supported (pending). Duplicate scan prevention, 3-attempt retry with exponential backoff, full scan history.

### Module 10: Compliance Management — ✅ Complete

5 frameworks: ISO 27001, SOC 2 Type II, PCI DSS, HIPAA, CIS Controls. Controls CRUD, gap analysis summary, evidence file upload/download/delete (up to 10MB per file). Compliance reports generated from reports module.

### Module 11: Risk Engine — ✅ Complete

6-factor weighted formula: CVSS (base) + EPSS (exploit probability) + KEV (is known exploited) + asset criticality (riskLevel) + exposure level (dangerous ports) + businessImpact (1–10 slider). Risk levels: Critical, High, Medium, Low. Trends tracked over time.

### Module 12: Alerting — ✅ Complete (3 triggers not wired)

Channels: Email (Resend), Slack (webhook), Discord (webhook), Telegram (Bot API), Generic Webhook.

Firing triggers: `scan_complete`, `critical_finding`, `high_finding`, `new_finding`, `brand_threat`.

Not wired to auto-fire: `new_asset` (UI selectable but no dispatch on asset creation), `ssl_expiry` (no scheduled SSL expiry check), `compliance_failure` (no event fired on control status change). Real-time SSE stream delivers alerts to browser instantly.

### Module 13: Reporting — ✅ Complete (XLSX missing)

Report types: Executive, Technical, Compliance, Asset Inventory. Formats: PDF (client-side), CSV (server-side), JSON. XLSX not implemented. Reports downloadable from Reports page and Scan Reports page.

### Module 14: Attack Surface Graph — ✅ Complete

`GET /graph/attack-surface` returns Neo4j-style `{nodes, relationships, meta}`. Node prefixes: `org-`, `asset-`, `port-`, `finding-`, `cve-`. Relationships: OWNS, SUBDOMAIN_OF, RESOLVES_TO, EXPOSES, HAS_VULNERABILITY, REFERENCES_CVE. Frontend renders with D3 force simulation with zoom/pan/drag/click-through. No actual Neo4j — architecture is Neo4j-ready.

### Module 15: AI Security Copilot — ✅ Complete

Endpoints: explain-finding, remediation, executive-summary, compliance-guidance. LLM abstraction in `lib/llm.ts` (OpenAI GPT-4o-mini). Returns `null` gracefully when no API key. Per-user LLM settings (custom model, system prompt, API key override).

---

## Extra Modules (Beyond Original Spec)

These features were built on top of the original 15-module requirement:

| Feature | Description |
|---|---|
| **Brand Threat Detection** | Typosquatting/phishing permutation engine, dnstwist-style with 4000+ mutations, favihunter, risk scoring |
| **Takedown Requests** | Formal takedown workflow for malicious/impersonating domains |
| **Security Tools Library** | Full tool management — 40+ tools across 8 categories, pipeline config, real-time run output |
| **Packages / Pricing** | Pricing tiers, Stripe billing, checkout, subscription management |
| **Tenant Management (Super Admin)** | Full tenant CRUD with super_admin-only access |
| **Client Dashboard** | Dedicated view for client-role users showing only their org's data |
| **Real-time SSE Alerts** | Live browser notification stream without polling |
| **Account Manager System** | Account managers manage specific client organizations |
| **Queue Monitor** | BullMQ queue metrics and job status for super_admin |
| **AI Copilot Settings** | Per-user LLM config (model, system prompt, personal API key) |
| **Session Management** | View and revoke individual sessions from Account Settings |
| **Invitations** | Invite users by email with role pre-assignment |
| **Recursive Directory Fuzzing** | BFS depth-3, 2000 endpoint limit, multi-wordlist |
| **JavaScript Analysis** | Extract API keys/secrets from public JS bundles |
| **Parameter Discovery** | Active parameter fuzzing for injectable parameters |
| **Endpoint Discovery** | Crawl + passive endpoint enumeration |
| **Secrets Hunter** | Pattern-match secrets in pages, JS, `.git` exposure detection |
| **Commercial Intel Integrations** | Shodan, Fofa, Censys, IntelX, CriminalIP, VirusTotal, Hunter.io (all optional via platform settings) |
| **Cloud Recon** | S3/GCS/Azure/Firebase bucket permutation and exposure detection |
| **EPSS/KEV Enrichment** | Automated batch enrichment of all findings post-scan |
| **Audit Log Immutability** | PostgreSQL trigger prevents any UPDATE/DELETE on audit_logs |
| **Stripe Billing** | Full checkout flow, subscription management, billing portal |

---

## Lib Engines (Key Files)

| File | Purpose |
|---|---|
| `lib/llm.ts` | LLM abstraction — `llmComplete()`, `isLLMAvailable()`. Model: gpt-4o-mini. Returns null on missing key. |
| `lib/notifier.ts` | Alert dispatch — Email, Slack, Discord, Telegram, Webhook, SSE. `dispatchNotifications()` is the entry point. |
| `lib/techDetector.ts` | 400+ web technology fingerprints (headers, HTML, cookies, scripts) |
| `lib/nucleiScanner.ts` | 40+ vulnerability templates — exposed panels, CVEs, misconfigs, secrets |
| `lib/screenshotEngine.ts` | Puppeteer-based screenshot capture — homepage, login, admin |
| `lib/portScanner.ts` | Naabu/Masscan/Nmap/Shodan port scanner with CAP_NET_RAW fallback |
| `lib/subdomainScanner.ts` | Subfinder/Findomain/AlterX/DNSX subdomain enumeration |
| `lib/passiveDiscovery.ts` | WHOIS, DNS, SPF, DMARC, DKIM, crt.sh, ASN, Shodan, VirusTotal, Hunter |
| `lib/brandThreatRunner.ts` | Domain permutation engine — typosquatting detection |
| `lib/epssKev.ts` | Batch EPSS (first.org, 100/batch), CISA KEV (24h cache) |
| `lib/cloudRecon.ts` | AWS S3, GCS, Azure Blob, Firebase bucket enumeration |
| `lib/secretsHunter.ts` | Pattern-match secrets in pages and JS files |
| `lib/jsAnalyzer.ts` | Extract API keys/tokens from public JavaScript bundles |
| `lib/dirFuzzer.ts` | BFS directory fuzzing — depth 3, 2000 endpoint max |
| `lib/paramDiscovery.ts` | Parameter fuzzing and injection point discovery |
| `lib/endpointDiscovery.ts` | Passive endpoint crawling + enumeration |
| `lib/nvdLookup.ts` | NVD CVE enrichment — 6500ms delay (no key), 650ms (with key) |
| `lib/hunterOsint.ts` | Hunter.io domain email intelligence |
| `lib/email.ts` | Nodemailer/Resend email dispatch |
| `lib/auth.ts` | JWT issue/verify, requireAuth middleware, requireRole middleware |
| `lib/cache.ts` | Simple in-memory TTL cache (used for EPSS, KEV, Shodan) |
| `lib/redis.ts` | Redis client with graceful fallback when REDIS_URL absent |
| `lib/sseManager.ts` | Server-Sent Events manager for real-time alert delivery |
| `lib/seedPlatform.ts` | Demo seed data — 5 assets, 6 findings, risk scores, compliance controls |
| `lib/audit.ts` | `logAudit()` helper — writes immutable audit log entries |
| `lib/stripeClient.ts` | Stripe SDK init, product/subscription helpers |
| `lib/webhookHandlers.ts` | Stripe webhook event handlers |

---

## Architecture Decisions

- **Contract-first API**: OpenAPI spec (`lib/api-spec/openapi.yaml`) is the single source of truth. Run `pnpm --filter @workspace/api-spec run codegen` after any change. Never write API fetch code by hand — use generated hooks.
- **JWT + sessionStorage**: Access token (15 min) in sessionStorage. Refresh token (7 days) in DB. Token injected via `setAuthTokenGetter` in the custom fetch wrapper.
- **Orval `{ data: ... }` wrapper**: All mutations require `mutateAsync({ data: { field } })` — never raw objects. This is an Orval codegen convention.
- **Multi-tenant by JWT**: `tenantId` is extracted from JWT on every request. No route trusts a client-provided tenantId.
- **toAssetResponse() explicit fields**: `assets.ts` `toAssetResponse()` manually lists every field. Any new DB column must be explicitly added or it silently vanishes from API responses.
- **beatScheduler supersedes scanScheduler**: `beatScheduler.ts` is the primary scheduler. `scanScheduler.ts` is legacy — only `finalizeScannedAssets()` from it is still used.
- **Express route ordering**: Static sub-paths (e.g. `/scans/pipeline-run`) must be registered BEFORE param routes (`/scans/:scanId`) to avoid shadowing.
- **No direct Zod imports in API server**: esbuild cannot resolve the `zod` package directly in the API server. Always use `@workspace/api-zod` generated schemas.
- **Pipeline variable naming**: `getPlatformSetting("shodan_api_key")` returns the value stored as `shodanKey`. When passing to `PassiveDiscoveryOptions`, it must be `{ shodanApiKey: shodanKey }`.
- **apiFetch + FormData**: When body is `FormData`, do not set `Content-Type` — browser must set it (with the multipart boundary) automatically.
- **No nested `<Link>` in Wouter**: Never nest `<Link>` inside `<Link>`. Use `onClick + navigate` on the outer container instead.
- **`logAudit` userId cast**: Always use `as any` on the userId arg — pre-existing TS quirk in the esbuild build that doesn't block runtime.
- **Drizzle undefined columns**: Passing undefined column refs to `db.select({})` causes `Object.entries(null)` crash. Always verify column names against schema before using in queries.
- **Email circular import**: `email.ts` imports from `platformSettings.ts`. `notifier.ts` imports from `email.ts`. Do NOT import `NotificationEvent` from `notifier.ts` back into `email.ts` — define event types inline to break the loop.
- **Audit log immutability**: PostgreSQL trigger `enforce_audit_log_immutability` (SECURITY DEFINER) raises exception on any UPDATE or DELETE. This cannot be bypassed even by application code.
- **NVD rate limits**: Without API key: 5 req/30s → 6500ms delay. With key: 50 req/30s → 650ms delay. Key passed as `apiKey` header.
- **Favihunter**: Never set PYTHONPATH in subprocess env. The wrapper script adds sys.path internally.
- **TanStack Query queryKey**: Hooks like `useGetToolRun` require `queryKey` in query options or TypeScript errors block Vite HMR module reloads.

---

## Security Implementation

| Layer | Implementation |
|---|---|
| Rate limiting | `express-rate-limit`: auth routes 20 req/15min; global 200 req/15min |
| Secure headers | `helmet` — CSP disabled (proxy compat), HSTS, X-Frame-Options, X-Content-Type-Options |
| Input validation | Zod schemas on all route inputs (body, params, query) |
| SQL injection | Drizzle ORM parameterized queries throughout — no raw SQL string interpolation |
| XSS | React's built-in escaping + Helmet headers |
| CSRF | SPA + JWT Bearer headers inherently CSRF-safe; no CSRF tokens for form submissions |
| Auth brute force | Rate limiter on all `/api/auth/*` routes |
| Password storage | bcrypt with salt rounds |
| Secrets management | Replit Secrets for env vars; sensitive API keys in `platform_settings` DB table (tenant-scoped) |
| Tenant isolation | JWT tenantId + Drizzle WHERE clause + PostgreSQL RLS on all 22 tenant tables |
| Audit trail | Immutable `audit_logs` table with PostgreSQL trigger preventing UPDATE/DELETE |
| RBAC | `requireRole()` middleware; role hierarchy: super_admin > admin > manager > client |

---

## Gotchas

- After editing API server routes, the workflow must restart to rebuild the esbuild bundle.
- Orval mutations wrap body in `{ data: ... }` — do NOT pass raw objects to `mutateAsync`.
- Run `pnpm --filter @workspace/api-spec run codegen` after any OpenAPI spec change.
- The API server listens on port 8080 but is accessed via the proxy at `localhost:80/api`.
- `toAssetResponse()` in `assets.ts` manually lists every field — new DB columns must be added explicitly.
- `shodanKey` (from `getPlatformSetting`) must be passed as `shodanApiKey` to `PassiveDiscoveryOptions`.
- Never set PYTHONPATH when calling favihunter Python subprocess.
- `beatScheduler.ts` is the primary scheduler — do not start `scanScheduler.ts` `runScheduler()` alongside it.
- Drizzle `db.select({})` with undefined column refs crashes with `Object.entries(null)`.
- `assetsTable` has no `status` or `riskScore` columns — use `verificationStatus` and `riskLevel`.
- `logAudit` userId always needs `as any` cast.
- `useListAssets()` returns `Asset[]` directly — not `{ assets: Asset[] }`.

---

## Pending / Not Implemented

1. **Module 8 — Go Agent**: Entire internal agent system not built (Windows/Linux/macOS binary, registration, host data collection).
2. **XLSX report format**: Only PDF, CSV, JSON exist. No Excel export.
3. **Custom cron expressions**: Scan scheduling supports only hourly/daily/weekly/monthly. No arbitrary cron syntax.
4. **3 alert triggers not wired end-to-end**: `new_asset` (no dispatch on creation), `ssl_expiry` (no scheduled check), `compliance_failure` (no event on status change).
5. **Finding evidence file uploads**: Findings have comments only. File evidence uploads exist on compliance controls, not on findings.
6. **API versioning**: All routes at `/api/` — no `/api/v1/` prefix.
7. **Docker + Docker Compose**: No Dockerfiles or docker-compose.yml.
8. **Kubernetes + Helm**: Not started.
9. **MinIO**: Screenshots stored as base64 in PostgreSQL.
10. **OpenSearch**: Replaced with PostgreSQL full-text search.
11. **Platform analytics dashboard (super admin)**: Queue monitor exists; no full cross-tenant analytics.
12. **Separate roles/permissions tables**: Role is a column in users table; no fine-grained permission table.
13. **DB table partitioning**: No partitioning strategy implemented for large-scale findings.
14. **Redis as required service**: Optional only; platform runs on in-memory fallback.
15. **Reverse WHOIS**: Basic coverage; no dedicated reverse WHOIS API service.
16. **Cloud account verification (full)**: Basic only; not integrated with AWS/Azure/GCP IAM APIs.

---

## User Preferences

_Populate as you build — explicit user instructions worth remembering across sessions._
