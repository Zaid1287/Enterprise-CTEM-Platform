# Sentinelware CTEM Platform — Complete Technical Documentation

> **Version:** 1.0  
> **Last Updated:** June 2026  
> **Classification:** Internal Engineering Reference

---

## Table of Contents

1. [Platform Overview](#1-platform-overview)
2. [Architecture Overview](#2-architecture-overview)
3. [Technology Stack](#3-technology-stack)
4. [Project Structure](#4-project-structure)
5. [Database Schema](#5-database-schema)
6. [Authentication & Authorization](#6-authentication--authorization)
7. [API Design & Contracts](#7-api-design--contracts)
8. [Module Reference — All 15+ Modules](#8-module-reference)
   - 8.1 Dashboard
   - 8.2 Asset Inventory
   - 8.3 Asset Groups
   - 8.4 Discovery & Scans
   - 8.5 Vulnerability Findings
   - 8.6 Risk Scoring
   - 8.7 Compliance Management
   - 8.8 Alerting
   - 8.9 Reports & Scan Reports
   - 8.10 AI Copilot
   - 8.11 Audit Logs
   - 8.12 User Management
   - 8.13 Tenant Settings
   - 8.14 Security Tools
   - 8.15 Packages
   - 8.16 Takedown Requests
   - 8.17 Account Manager / My Clients
   - 8.18 Screenshots
   - 8.19 Technology Detections
   - 8.20 Platform Settings (Super Admin)
9. [Scan Engine — Deep Dive](#9-scan-engine--deep-dive)
   - 9.1 Scan Phases
   - 9.2 Phase 1: Reconnaissance
   - 9.3 Phase 2: Port Scanning
   - 9.4 Phase 3: Web Reconnaissance
   - 9.5 Phase 4: Vulnerability & Secrets
   - 9.6 Phase 5: SSL/TLS Analysis
   - 9.7 How Scan Results Are Stored
   - 9.8 Real CVE Enrichment (NVD + Shodan)
   - 9.9 Secrets Detection (25 Patterns)
   - 9.10 Scan Scheduler
10. [Security Tools Catalog](#10-security-tools-catalog)
11. [Multi-Tenancy Model](#11-multi-tenancy-model)
12. [Frontend Architecture](#12-frontend-architecture)
13. [Environment Variables](#13-environment-variables)
14. [Local Development Setup](#14-local-development-setup)
15. [Production Server Installation](#15-production-server-installation)
    - 15.1 Server Prerequisites
    - 15.2 System Tools to Install
    - 15.3 Application Installation
    - 15.4 Nginx Reverse Proxy
    - 15.5 Systemd Services
    - 15.6 SSL with Certbot
    - 15.7 PostgreSQL Setup
16. [Operational Runbooks](#16-operational-runbooks)
17. [Pending / Roadmap Items](#17-pending--roadmap-items)

---

## 1. Platform Overview

**Sentinelware** is an enterprise-grade, multi-tenant **Continuous Threat Exposure Management (CTEM)** platform. It provides organisations with a centralised system to:

- **Discover** internet-facing assets (domains, IPs, URLs, cloud infrastructure)
- **Scan** assets using an integrated pipeline of 30+ open-source security tools
- **Enrich** findings with real CVE data from NVD and Shodan
- **Prioritise** vulnerabilities using CVSS, EPSS, and KEV (Known Exploited Vulnerabilities)
- **Track** compliance posture across SOC2, ISO27001, PCI-DSS, NIST CSF, HIPAA, GDPR, and CIS Controls
- **Alert** on new critical exposures in real time
- **Report** on security posture to technical and executive stakeholders
- **Manage** multiple customer tenants from a single super-admin instance

CTEM is a Gartner-defined security programme that moves organisations from reactive vulnerability management to continuous, prioritised exposure reduction. Sentinelware implements the full CTEM lifecycle:

```
Scoping → Discovery → Prioritisation → Validation → Mobilisation
```

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        BROWSER (User)                           │
│                React 19 SPA  /  Vite / Tailwind v4              │
└───────────────────────────┬─────────────────────────────────────┘
                            │  HTTPS  (path-based routing)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                     REVERSE PROXY (Nginx)                       │
│         /          → port 23203   (React SPA / Vite)            │
│         /api       → port 8080    (Express API)                 │
└────────────────────┬────────────────────┬───────────────────────┘
                     │                    │
          ┌──────────▼──────┐   ┌─────────▼────────┐
          │  Frontend (Vite) │   │  API Server       │
          │  React 19 + TS   │   │  Express 5 + TS   │
          │  Port: 23203     │   │  Port: 8080       │
          └──────────────────┘   └─────────┬─────────┘
                                           │
                                 ┌─────────▼─────────┐
                                 │  PostgreSQL DB     │
                                 │  Drizzle ORM       │
                                 │  21 tables         │
                                 └───────────────────┘
```

### Key Design Principles

| Principle | Implementation |
|---|---|
| **Contract-first API** | OpenAPI spec → Orval codegen → typed React Query hooks |
| **Multi-tenant isolation** | All DB queries scoped by `tenantId` from JWT |
| **Zero secret exposure** | JWT payload contains only `userId`, `tenantId`, `email`, `role` |
| **Async scan execution** | Scans run in `setImmediate` background loops — never block HTTP |
| **Immutable audit trail** | Every mutation is logged to `audit_logs` table |
| **Role-based access** | 4 roles enforced at the API middleware layer |

---

## 3. Technology Stack

### Backend

| Technology | Version | Purpose |
|---|---|---|
| **Node.js** | 24.x | Runtime |
| **TypeScript** | 5.9 | Type safety |
| **Express** | 5.x | HTTP framework |
| **Drizzle ORM** | 0.45.x | Type-safe DB queries |
| **PostgreSQL** | 16+ | Primary database |
| **pg** | 8.20.x | PostgreSQL Node driver |
| **drizzle-kit** | 0.31.x | DB schema push / migrations |
| **jsonwebtoken** | 9.x | JWT signing & verification |
| **bcryptjs** | 3.x | Password hashing (cost factor 12) |
| **pino** | 9.x | Structured JSON logging |
| **pino-http** | 10.x | Request logging middleware |
| **esbuild** | 0.27.3 | ESM bundle compilation |
| **multer** | 2.x | Multipart file uploads |
| **puppeteer** | 25.x | Headless browser (screenshots) |
| **resend** | 6.x | Transactional email SDK |
| **zod** | 3.25.x | Runtime schema validation |
| **cors** | 2.x | Cross-origin resource sharing |

### Frontend

| Technology | Version | Purpose |
|---|---|---|
| **React** | 19.1.0 | UI framework |
| **TypeScript** | 5.9 | Type safety |
| **Vite** | 7.x | Dev server + bundler |
| **Tailwind CSS** | 4.x | Utility-first CSS |
| **wouter** | 3.3.x | Lightweight client-side router |
| **TanStack Query** | 5.x | Server state, caching, mutations |
| **Zustand** | 5.x | Auth global state |
| **Recharts** | 2.x | Data visualisation charts |
| **Radix UI** | Various | Accessible headless components |
| **lucide-react** | 0.545.x | Icon library |
| **Orval** (codegen) | — | OpenAPI → React Query hooks |
| **framer-motion** | 12.x | Animations |
| **date-fns** | 3.x | Date formatting |

### Infrastructure / Toolchain

| Technology | Purpose |
|---|---|
| **pnpm** | Monorepo package manager with workspace catalog |
| **pnpm workspaces** | Shared libs (`lib/*`) + deployable artifacts (`artifacts/*`) |
| **drizzle-zod** | Auto-generate Zod schemas from Drizzle table definitions |
| **nmap** | Network port scanner (runtime tool, not npm) |
| **whois** | Domain registration lookup (system binary) |
| **openssl** | TLS certificate inspection (system binary) |

---

## 4. Project Structure

```
workspace/
├── artifacts/
│   ├── api-server/                 # Express API server
│   │   ├── src/
│   │   │   ├── app.ts              # Express app setup (cors, json, routes)
│   │   │   ├── index.ts            # Server entry (binds port, seeds DB)
│   │   │   ├── routes/             # One file per module (25 route files)
│   │   │   │   ├── auth.ts         # POST /login, /register, /refresh, /logout
│   │   │   │   ├── assets.ts       # CRUD assets + bulk import
│   │   │   │   ├── findings.ts     # CRUD vulnerability findings
│   │   │   │   ├── pipelineScans.ts# Scan engine (2556 lines)
│   │   │   │   ├── platformSettings.ts # Super admin API keys
│   │   │   │   └── ...             # 20+ other modules
│   │   │   └── lib/
│   │   │       ├── auth.ts         # JWT sign/verify, requireAuth middleware
│   │   │       ├── audit.ts        # logAudit() helper
│   │   │       ├── nvdLookup.ts    # Real CVE lookup (NVD API + Shodan)
│   │   │       ├── portScanner.ts  # nmap wrapper
│   │   │       ├── subdomainScanner.ts  # Subfinder/DNS enumeration
│   │   │       ├── nucleiScanner.ts     # Nuclei template scanner
│   │   │       ├── techDetector.ts      # Technology fingerprinting
│   │   │       ├── screenshotEngine.ts  # Puppeteer screenshot capture
│   │   │       ├── secretsHunter.ts     # 25-pattern secrets detector
│   │   │       ├── dirFuzzer.ts         # Directory brute-force
│   │   │       ├── jsAnalyzer.ts        # JS endpoint extractor
│   │   │       ├── paramDiscovery.ts    # HTTP parameter discovery
│   │   │       ├── cloudRecon.ts        # Cloud bucket enumeration
│   │   │       ├── seedPlatform.ts      # 35+ built-in tool definitions
│   │   │       ├── scanScheduler.ts     # Cron-based recurring scans
│   │   │       └── logger.ts            # Pino logger singleton
│   │   ├── build.mjs               # esbuild config
│   │   └── package.json
│   │
│   └── ctem-platform/              # React frontend
│       ├── src/
│       │   ├── App.tsx             # Router + lazy page imports
│       │   ├── pages/              # 30 page components
│       │   ├── components/
│       │   │   ├── layout/         # AppLayout, Sidebar, Navbar
│       │   │   └── ui/             # Radix-based design system (50+ components)
│       │   ├── hooks/
│       │   │   └── useAuth.ts      # Zustand auth store
│       │   └── lib/
│       │       ├── auth.ts         # Token refresh logic
│       │       ├── custom-fetch.ts # Injects Bearer token on every request
│       │       └── utils.ts        # cn(), formatDateTime(), severityBgColor()
│       └── package.json
│
├── lib/
│   ├── api-spec/
│   │   ├── openapi.yaml            # Source of truth — 3152-line API contract
│   │   └── orval.config.ts         # Codegen config
│   ├── api-client-react/
│   │   └── src/generated/api.ts    # Generated React Query hooks
│   ├── api-zod/
│   │   └── src/generated/api.ts    # Generated Zod validation schemas
│   └── db/
│       ├── src/
│       │   ├── index.ts            # Re-exports db client + all tables
│       │   └── schema/             # 21 Drizzle table definitions
│       └── drizzle.config.ts
│
├── pnpm-workspace.yaml             # Package catalog + workspace config
├── tsconfig.base.json              # Shared strict TS defaults
├── tsconfig.json                   # Solution file for composite libs
└── package.json                    # Root scripts (typecheck, build)
```

---

## 5. Database Schema

All 21 tables and their purpose:

| Table | Purpose |
|---|---|
| `tenants` | One row per organisation. All data scoped by `tenant_id`. |
| `users` | Platform users. Roles: `super_admin`, `admin`, `user`, `account_manager`. Password stored as bcrypt hash. |
| `assets` | Discovered/registered assets. Types: `domain`, `ip`, `url`, `host`, `cloud`, `mobile`, `api`, `iot`. |
| `asset_groups` | Named groups of assets for bulk scanning and reporting. |
| `scans` | Scan sessions — one row per scan run, holds status, config, result summary. |
| `scan_asset_results` | Per-asset results within a scan. Stores JSON blobs: ports, subdomains, endpoints, DNS records, HTTP headers, SSL cert, screenshots, CVEs, secrets. |
| `findings` | Vulnerability findings. Each row: CVE ID, CVSS, EPSS, KEV flag, title, description, remediation, status, affected asset. |
| `risk_scores` | Time-series risk scores per asset and aggregate per tenant. |
| `compliance` | Per-tenant compliance controls across 7 frameworks. Each row: framework, control ID, status (pass/fail/partial). |
| `alerts` | Security alerts. Types: new_vulnerability, critical_exposure, ssl_expiry, new_asset, compliance_failure, scan_complete. |
| `audit_logs` | Immutable write-append audit trail. Every mutating API call writes a row. |
| `reports` | Generated report metadata (type, created_at, config). |
| `security_tools` | Tool catalog — 35+ built-in tools + user-added tools. |
| `tool_pipeline_steps` | Ordered pipeline — which tools run in which sequence per tenant. |
| `scan_schedules` | Cron-based recurring scan configurations. |
| `packages` | Software package inventory per asset (name, version, vendor). |
| `takedown_requests` | Infrastructure takedown tracking (phishing domains, malicious IPs). |
| `account_manager_clients` | Maps account_manager users to the tenants they manage. |
| `invitations` | Email invitation tokens for new user onboarding. |
| `user_ai_settings` | Per-user AI model preferences (model, temperature, system prompt). |
| `technology_detections` | Technologies detected per asset (framework, version, confidence). |
| `screenshots` | Headless browser screenshots captured per URL during scans. |
| `platform_settings` | Super-admin key-value store for third-party API credentials. |

### Key Relationships

```
tenants ──< users
tenants ──< assets ──< scan_asset_results >── scans
tenants ──< findings >── assets
tenants ──< compliance
tenants ──< alerts
tenants ──< security_tools
tenants ──< reports
audit_logs >── users (actor)
```

---

## 6. Authentication & Authorization

### JWT Token Flow

```
1. POST /api/auth/login  { email, password }
      │
      ▼
   bcrypt.compare(password, hash)  [cost factor 12]
      │
      ▼
   signAccessToken(payload)   → expires in 8 hours
   signRefreshToken(payload)  → expires in 7 days
      │
      ▼
   Response: { accessToken, refreshToken, user }
      │
      ▼
   Client stores in sessionStorage
   Every request: Authorization: Bearer <accessToken>

2. On 401 → POST /api/auth/refresh  { refreshToken }
      │
      ▼
   verifyToken(refreshToken) → new accessToken
      │
   Client retries original request
   If refresh fails → logout()
```

### JWT Payload

```typescript
interface JwtPayload {
  userId: number;
  tenantId: number;    // All queries are automatically scoped to this
  email: string;
  role: "super_admin" | "admin" | "user" | "account_manager";
}
```

### Middleware

```typescript
requireAuth          // Verifies Bearer token, attaches req.user
requireRole("admin") // Checks role after requireAuth
```

### Roles & Permissions

| Role | Scope | Permissions |
|---|---|---|
| `super_admin` | All tenants | Full access including platform settings, all tenants, packages |
| `admin` | Own tenant | Full access to all modules within tenant |
| `user` | Own tenant | Read access + limited write (no user management, no tenant settings) |
| `account_manager` | Assigned tenants | Read access + client management |

### Password Security

- Hashed with **bcrypt**, cost factor **12** (≈300ms per hash, resistant to GPU cracking)
- No plaintext passwords stored anywhere
- Password reset uses a one-time token stored in DB, expires in 1 hour

---

## 7. API Design & Contracts

### Contract-First Approach

The API is defined **once** in `lib/api-spec/openapi.yaml` (3152 lines). From this single source of truth:

1. **Orval** generates React Query hooks in `lib/api-client-react/src/generated/api.ts`
2. **Orval** generates Zod schemas in `lib/api-zod/src/generated/api.ts`
3. API server route handlers use the Zod schemas to validate inputs

### Regenerating After Spec Changes

```bash
pnpm --filter @workspace/api-spec run codegen
```

### API Base Path

All endpoints are prefixed with `/api`. The reverse proxy routes `/api/*` to port 8080.

### Key API Endpoints Summary

| Module | Endpoints |
|---|---|
| **Auth** | `POST /auth/login`, `/auth/register`, `/auth/refresh`, `/auth/logout`, `/auth/forgot-password`, `/auth/reset-password` |
| **Assets** | `GET/POST /assets`, `GET/PUT/DELETE /assets/:id`, `POST /assets/import` |
| **Asset Groups** | `GET/POST /asset-groups`, `GET/PUT/DELETE /asset-groups/:id` |
| **Scans** | `GET/POST /scans`, `GET /scans/:id`, `DELETE /scans/:id` |
| **Pipeline Scans** | `POST /scans/pipeline-run`, `GET /scans/:id/progress`, `POST /scans/:id/stop` |
| **Scan Schedules** | `GET/POST /scan-schedules`, `PUT/DELETE /scan-schedules/:id`, `POST /scan-schedules/:id/run-now` |
| **Findings** | `GET/POST /findings`, `GET/PUT/DELETE /findings/:id` |
| **Risk** | `GET /risk/scores`, `GET /risk/trend` |
| **Compliance** | `GET/POST /compliance/controls`, `GET /compliance/frameworks` |
| **Alerts** | `GET /alerts`, `GET /alerts/:id`, `PUT /alerts/:id`, `POST /alerts/mark-all-read` |
| **Alert Rules** | `GET/POST /alert-rules`, `DELETE /alert-rules/:id` |
| **Reports** | `GET/POST /reports`, `GET /reports/:id` |
| **Scan Reports** | `GET /scan-reports`, `GET /scan-reports/:id` |
| **AI Copilot** | `POST /ai/chat`, `GET /ai/sessions`, `DELETE /ai/sessions/:id` |
| **Audit Logs** | `GET /audit-logs` |
| **Users** | `GET /users`, `PUT /users/:id`, `DELETE /users/:id` |
| **Tenants** | `GET /tenants`, `GET/PUT /tenants/:id` (super_admin) |
| **Tools** | `GET/POST /tools`, `PUT/DELETE /tools/:id`, `POST /tools/:id/run`, `GET /tools/pipeline`, `PUT /tools/pipeline` |
| **Packages** | `GET /packages`, `POST /packages`, `DELETE /packages/:id` |
| **Takedowns** | `GET/POST /takedowns`, `PUT /takedowns/:id` |
| **Invitations** | `POST /invitations`, `POST /invitations/accept` |
| **Screenshots** | `GET /screenshots/:assetId` |
| **Platform Settings** | `GET/PUT /platform/settings`, `GET /platform/settings/raw/:key` (super_admin only) |

### Request/Response Convention

All mutations send a `{ data: ... }` wrapped body — this is the Orval codegen convention:

```typescript
// ✅ Correct
mutateAsync({ findingId: 1, data: { status: "mitigated" } })

// ❌ Wrong — will fail type check
mutateAsync({ findingId: 1, status: "mitigated" })
```

---

## 8. Module Reference

### 8.1 Dashboard

**Page:** `/dashboard`  
**Route file:** `routes/dashboard.ts`

Displays the security posture overview:

- **Stats cards:** total assets, active findings (open + in_progress), aggregate risk score, unread alert count
- **Severity breakdown:** pie chart showing critical/high/medium/low finding counts
- **Risk trend:** line chart showing risk score over the past 30 days (calculated from `risk_scores` table)
- **Findings over time:** bar chart of new findings per week for the past 8 weeks
- **Asset growth:** asset count trend over past 30 days
- **Recent alerts widget:** last 5 unread alerts
- **Recent findings widget:** last 5 critical/high findings
- **Compliance health:** percentage compliance per framework

All data is computed from live DB queries, not cached or fake.

---

### 8.2 Asset Inventory

**Page:** `/assets`  
**Route file:** `routes/assets.ts`

The central register of all internet-facing assets belonging to a tenant.

**Asset Types:**
- `domain` — apex domains (example.com)
- `ip` — IPv4/IPv6 addresses
- `url` — specific URLs (https://api.example.com/v2)
- `host` — internal hostnames
- `cloud` — cloud resource identifiers (AWS ARN, GCP resource ID)
- `mobile` — mobile app bundle IDs
- `api` — API service endpoints
- `iot` — IoT device identifiers

**Asset Detail Page (`/assets/:id`) shows:**
- Metadata (type, status, IP, operating system, tags)
- Technology detections (fingerprinted frameworks, languages, CDNs)
- Open ports and services from last scan
- Related findings count and severity breakdown
- Scan history timeline
- Screenshots captured during last scan
- DNS records (A, AAAA, MX, TXT, NS, CNAME)
- SSL certificate details
- WHOIS registration data

**Bulk Import:** CSV upload endpoint `POST /assets/import` — accepts CSV with `name,type,value` columns.

---

### 8.3 Asset Groups

**Page:** `/asset-groups`  
**Route file:** `routes/assetGroups.ts`

Named logical groups of assets used for:
- Targeted bulk scanning (run a scan against a group)
- Report scoping (compliance/executive report for a business unit)
- Risk aggregation per business unit

---

### 8.4 Discovery & Scans

**Page:** `/scans`  
**Route file:** `routes/scans.ts` + `routes/pipelineScans.ts`

See **Section 9** for the full scan engine deep-dive.

---

### 8.5 Vulnerability Findings

**Page:** `/findings`  
**Route file:** `routes/findings.ts`

Central vulnerability management view.

**Finding fields:**
- `cve` — CVE identifier (e.g. CVE-2024-1234)
- `title` — human-readable vulnerability name
- `description` — full vulnerability description from NVD
- `severity` — critical / high / medium / low / info
- `cvssScore` — CVSS v3 base score (0.0–10.0)
- `epssScore` — Exploit Prediction Scoring System probability (0.0–1.0)
- `isKev` — boolean, whether in CISA Known Exploited Vulnerabilities catalogue
- `importanceScore` — derived priority score: `cvss × epss × (isKev ? 2.5 : 1.0)`
- `status` — open / in_progress / accepted_risk / false_positive / mitigated
- `affectedAssetId` — link to the affected asset
- `cwe` — CWE weakness category
- `remediation` — step-by-step fix guidance

**Inline Status Change:** Status can be changed directly in the findings table via a dropdown without opening a detail view.

**Finding Detail Page (`/findings/:id`):** Full CVE details, CVSS vector, affected asset link, remediation steps, timeline of status changes.

---

### 8.6 Risk Scoring

**Page:** `/risk`  
**Route file:** `routes/risk.ts`

Risk score calculation per asset, aggregated to tenant level:

```
Asset Risk Score = Σ (finding.cvssScore × epssWeight × kevMultiplier)

where:
  epssWeight    = 1 + (finding.epssScore × 2)     // boosts high-exploitation probability
  kevMultiplier = finding.isKev ? 2.5 : 1.0        // strong boost for known-exploited CVEs
```

Scores are stored time-series in `risk_scores` to power the trend chart.

---

### 8.7 Compliance Management

**Page:** `/compliance`  
**Route file:** `routes/compliance.ts`

Tracks compliance posture against 7 frameworks:

| Framework | Controls |
|---|---|
| SOC 2 | CC1–CC9 (Security, Availability, Confidentiality, Processing Integrity, Privacy) |
| ISO 27001 | A.5–A.18 (Information Security Controls) |
| PCI-DSS | Requirements 1–12 |
| NIST CSF | Identify, Protect, Detect, Respond, Recover |
| HIPAA | Administrative, Physical, Technical Safeguards |
| GDPR | Articles 5, 25, 32, 33, 34 |
| CIS Controls | Implementation Groups 1–3 |

Each control has a status: `pass`, `fail`, `partial`, `not_applicable`.

Compliance percentage = `pass_count / (total - not_applicable)`.

---

### 8.8 Alerting

**Page:** `/alerts`  
**Route file:** `routes/alerts.ts`

**Alert Types:**
- `new_vulnerability` — new critical/high finding discovered
- `critical_exposure` — asset exposed with critical vulnerability
- `ssl_expiry` — SSL certificate expiring within 30 days
- `new_asset` — new asset discovered by scan
- `compliance_failure` — compliance control dropped to fail
- `scan_complete` — scan finished (with summary)

**Alert Detail Page (`/alerts/:id`):** Shows full alert message, severity badge, type label, received timestamp, auto-marks read on load, links to related asset or finding.

**Alert Rules:** Configurable rules that auto-create alerts based on triggers. Channel options: email, slack, webhook.

---

### 8.9 Reports & Scan Reports

**Page:** `/reports`, `/scan-reports`  
**Route file:** `routes/reports.ts`

**Report Types:**
- `executive` — high-level risk summary for leadership
- `technical` — detailed findings list for engineering teams
- `compliance` — framework-by-framework compliance posture
- `vulnerability` — full CVE catalogue with remediation priorities

**Scan Report Detail Page (`/scan-reports/:id`):**
The richest output in the platform. Contains:
- Per-asset findings with CVE IDs, CVSS, EPSS
- Discovered open ports and services
- Technology fingerprinting results
- Discovered subdomains
- Discovered endpoints/URLs
- DNS record set
- SSL certificate details (issuer, SANs, expiry, TLS version)
- WHOIS registration data
- Detected secrets (patterns matched, not raw values)
- Cloud asset exposures
- JavaScript analysis results
- HTTP security header analysis

---

### 8.10 AI Copilot

**Page:** `/ai-copilot`  
**Route file:** `routes/ai.ts`

Chat interface powered by an LLM backend. Features:
- Persistent conversation sessions stored in DB
- Per-user model settings (model selection, temperature, system prompt override)
- Suggestions: summarise findings, explain a CVE, draft a remediation plan, generate an executive risk summary

---

### 8.11 Audit Logs

**Page:** `/audit-logs`  
**Route file:** `routes/auditLogs.ts`

Immutable append-only log of all platform actions. Every mutating API call writes a row via `logAudit()`.

**Log fields:** actor (userId, email, role), action (created/updated/deleted/viewed), resourceType, resourceId, details JSON, IP address, timestamp.

**Filters:** actor, action type, resource type, date range.

---

### 8.12 User Management

**Page:** `/settings/users`  
**Route file:** `routes/users.ts` + `routes/invitations.ts`

- List all users in the tenant
- Invite new users by email (generates a one-time invite token, stores in `invitations` table)
- Edit user roles
- Deactivate/reactivate users
- Delete users (soft-delete preserving audit trail)

---

### 8.13 Tenant Settings

**Page:** `/settings/tenant`  
**Route file:** `routes/tenants.ts`

Per-tenant configuration:
- Organisation name
- Primary domain
- Logo URL
- Notification preferences
- Subscription tier display

---

### 8.14 Security Tools

**Page:** `/tools`  
**Route file:** `routes/tools.ts` + `routes/pipelineScans.ts`

The security tools module has three sub-views:

**Tool Library tab:**
- 35+ built-in tools pre-seeded for every tenant
- Add custom tools with GitHub URL, install/run/update commands, output format
- Edit any tool via the edit dialog (name, category, description, commands)
- Activate/deactivate tools
- 15 tools per page with pagination
- Run individual tools against assets

**Pipeline tab:**
- Drag-reorder tools into an execution pipeline
- Tools run in the configured sequence during pipeline scans
- Each tool is assigned to a phase (1=Recon, 2=Ports, 3=Web, 4=Vuln, 5=SSL)

**Run History tab:**
- Logs of all past tool runs
- Per-run status, duration, findings count
- Expandable output viewer

---

### 8.15 Packages

**Page:** `/packages`  
**Route file:** `routes/packages.ts`

Software package inventory:
- Package name, version, vendor per asset
- Cross-references package version against known vulnerable versions in findings
- Supports manual entry and import

---

### 8.16 Takedown Requests

**Page:** `/takedowns`  
**Route file:** `routes/takedowns.ts`

Tracks infrastructure takedown requests:
- Phishing domains impersonating the organisation
- Malicious IPs or URLs hosting malware
- Status workflow: submitted → in_progress → completed / rejected
- Evidence attachment
- Notified authority (CERT, hosting registrar, ISP)

---

### 8.17 Account Manager / My Clients

**Page:** `/my-clients`  
**Route file:** `routes/accountManager.ts`

For users with the `account_manager` role:
- View all tenants assigned to them
- Access each tenant's dashboard and findings
- Create client-specific executive reports

---

### 8.18 Screenshots

**Route file:** `routes/screenshots.ts`  
**Engine:** `lib/screenshotEngine.ts`

During scans, Puppeteer captures screenshots of:
- Root page (`/`)
- Login page (`/login`)
- Admin panel (`/admin`)
- Signup page (`/signup`)
- Any API documentation endpoints

Screenshots stored as base64 in `screenshots` table, displayed in Asset Detail page.

---

### 8.19 Technology Detections

**Engine:** `lib/techDetector.ts`

Detects 60+ technology categories from HTTP responses:
- CMS: WordPress, Drupal, Joomla, Ghost
- Frameworks: React, Vue, Angular, Next.js, Laravel, Django, Rails, Spring
- CDN: Cloudflare, Fastly, Akamai, AWS CloudFront
- Analytics: Google Analytics, Mixpanel, Segment, Hotjar
- Security: Cloudflare WAF, Imperva, Sucuri
- Web servers: Nginx, Apache, IIS, Caddy
- Databases (via error pages/headers): MySQL, PostgreSQL, MongoDB, Redis
- Cloud platforms: AWS, GCP, Azure

Detection signal sources: `X-Powered-By`, `Server`, `X-Generator`, HTML `<meta name="generator">`, JS global variables, cookie names, script src patterns.

---

### 8.20 Platform Settings (Super Admin)

**Page:** `/settings/platform`  
**Route file:** `routes/platformSettings.ts`

Accessible only to `super_admin` role. Stores third-party API credentials in the `platform_settings` DB table.

**Keys managed:**

| Key | Category | Purpose |
|---|---|---|
| `resend_api_key` | Email | Resend.com API key for transactional emails |
| `smtp_host` / `smtp_port` / `smtp_user` / `smtp_pass` / `smtp_from` | Email | Custom SMTP configuration |
| `slack_webhook_url` | Notifications | Slack incoming webhook for alerts |
| `discord_webhook_url` | Notifications | Discord webhook for alerts |
| `shodan_api_key` | Scanning | Enables full Shodan API (CVE enrichment, CPEs, ports) |
| `nvd_api_key` | Scanning | Increases NVD rate limit from 5 to 50 req/30s |
| `virustotal_api_key` | Scanning | Domain/IP reputation lookups |
| `hunter_api_key` | OSINT | Employee email enumeration via Hunter.io |

Values are masked in the UI. The "reveal" button fetches the real value from `/platform/settings/raw/:key`.

---

## 9. Scan Engine — Deep Dive

### 9.1 Scan Phases

The scan engine (`pipelineScans.ts`, 2556 lines) executes in **5 ordered phases**:

```
Phase 1: Reconnaissance    — Passive discovery (subdomains, OSINT, cloud)
Phase 2: Port Scanning     — Active port/service enumeration
Phase 3: Web Recon         — HTTP probing, tech detection, endpoint discovery
Phase 4: Vuln & Secrets    — Vulnerability templates, secrets scanning, JS analysis
Phase 5: SSL/TLS Analysis  — Certificate inspection, TLS configuration audit
```

All phases run **asynchronously** in a `setImmediate` background loop. The HTTP response to `POST /scans/pipeline-run` returns immediately with the scan ID. Progress is tracked in-memory via `scanProgressMap` and polled by the frontend via `GET /scans/:id/progress`.

### 9.2 Phase 1: Reconnaissance

**Subdomain Enumeration (runs on `domain` type assets):**
- DNS A/AAAA/MX/TXT/NS/CNAME resolution via Node `dns/promises`
- `subfinder` — 40+ passive data sources (VirusTotal, Shodan, Chaos, DNSdb, etc.)
- `findomain` — Certificate Transparency log mining
- `dnsx` — active DNS brute-force with built-in wordlist
- `alterx` — subdomain permutation generation
- `theHarvester` — email, hostname, URL harvesting from public sources

**OSINT:**
- WHOIS registration data (registrar, registrant, creation/expiry dates)
- `ip-api.com` geolocation (country, ASN, ISP, city)
- Cloud provider detection from IP ranges (AWS, GCP, Azure, Cloudflare)

**Cloud Recon:**
- `cloud-enum` — S3, GCS, Azure Blob bucket enumeration from domain name patterns
- Firebase database exposure checking
- GrayhatWarfare bucket search

### 9.3 Phase 2: Port Scanning

**Tool:** `nmap -sT` (TCP connect scan, no raw sockets required)

```bash
nmap -sT -T4 --open -p 21,22,23,25,53,80,110,143,443,445,
     465,587,993,995,1433,1521,2181,3306,3389,5432,5900,
     6379,8080,8443,8888,9200,27017 <target>
```

- TCP connect scan used instead of SYN scan to avoid root requirement
- Top 28 ports by default (expanded if full-scan flag enabled)
- Service and version detection via banner grabbing
- Results stored as `ports[]` JSON array in `scan_asset_results`

**Also uses:**
- `naabu` / `masscan` — high-speed port scanners for large CIDR ranges
- `rustscan` — fast initial port list, feeds into nmap for service detection

### 9.4 Phase 3: Web Reconnaissance

**HTTP Probing via Node `fetch`:**
- HTTP status code, redirect chain
- All response headers (Server, X-Powered-By, X-Frame-Options, CSP, HSTS, etc.)
- Page title extraction from `<title>` tag
- Content-Length
- Cookie flags analysis (Secure, HttpOnly, SameSite)

**Technology Detection** (see Section 8.19)

**Endpoint/URL Discovery:**
- `gau` — GetAllURLs from Wayback Machine, CommonCrawl, OTX
- `waybackurls` — Internet Archive CDX API historical URLs
- `katana` — JS-aware active crawler with Puppeteer rendering
- `hakrawler` — fast HTML link extractor
- `feroxbuster` — active directory brute-force (240-path wordlist)
- `uro` — URL deduplication and normalisation

**JavaScript Analysis (`lib/jsAnalyzer.ts`):**
- Fetches all `<script src>` URLs from target pages
- Applies LinkFinder regex patterns to find embedded API endpoints
- Applies SecretFinder patterns to detect credentials in JS bundles
- Parses `fetch()`, `axios()`, `XMLHttpRequest` calls for API routes

**Parameter Discovery:**
- `paramspider` — mines historical URLs for real parameter names
- `arjun` — active parameter brute-force (~300 common names)

**WAF Detection:**
- Fingerprints WAF vendor from response headers and error page signatures
- Cloudflare, Imperva, Sucuri, AWS WAF, Akamai, Barracuda

**Screenshots** (see Section 8.18)

### 9.5 Phase 4: Vulnerability & Secrets

**Nuclei Scanner (`lib/nucleiScanner.ts`):**

Runs 40+ built-in detection templates:

*Exposed Admin Panels:* phpMyAdmin, Adminer, Kibana, Jenkins, Grafana, Prometheus, Consul, Elasticsearch, Redis Commander, MongoDB Express, Jupyter Notebook, Laravel Telescope, Symfony Profiler, Spring Boot Actuator

*Sensitive File Leaks:* `.env`, `.git/HEAD`, `wp-config.php`, `credentials.json`, AWS credentials file, SSH private keys, `.DS_Store`, `web.config`, `backup.sql`

*CORS Misconfiguration:* reflected-origin bypass, null-origin bypass, subdomain confusion, credential inclusion with wildcard

*Security Header Analysis:* Missing HSTS, missing CSP, missing X-Frame-Options, missing X-Content-Type-Options, permissive CSP

*Known CVEs:* CVE-2017-9841 (PHPUnit RCE via eval), CVE-2022-22947 (Spring Cloud Gateway SPEL), and others

**Secrets Detection (`lib/secretsHunter.ts`):**

Scans HTTP responses, HTML source, JS files, and API responses against **25 secret patterns**:

| Pattern | Severity |
|---|---|
| AWS Access Key ID (`AKIA[0-9A-Z]{16}`) | Critical |
| AWS Secret Access Key | Critical |
| GitHub Personal Token (`ghp_...`) | High |
| GitHub OAuth Token (`gho_...`) | High |
| Stripe Live Secret Key (`sk_live_...`) | Critical |
| OpenAI API Key (`sk-[48 chars]`) | High |
| Slack Bot Token (`xoxb-...`) | High |
| Google API Key (`AIza[35 chars]`) | High |
| RSA/EC Private Key (`-----BEGIN PRIVATE KEY-----`) | Critical |
| JWT Token | Medium |
| SendGrid API Key (`SG.xxx.xxx`) | High |
| SQL Connection String with credentials | Critical |
| MongoDB URI with credentials | Critical |
| Hardcoded Password | High |
| Basic Auth in URL | High |
| npm Auth Token | High |
| Docker Config Auth | High |
| Firebase Private Key | High |
| ... and 7 more | Various |

Each match records: pattern name, severity, CWE ID, remediation guidance.

### 9.6 Phase 5: SSL/TLS Analysis

**Engine:** Node `tls.connect()`

Inspects SSL/TLS configuration:
- Certificate issuer (CA name, O, OU)
- Subject Common Name and all Subject Alternative Names (SANs)
- Certificate valid-from and expiry date
- Days until expiry (triggers alert if < 30 days)
- TLS protocol version (TLS 1.0/1.1 flagged as weak)
- Cipher suites negotiated
- Certificate chain length
- Self-signed certificate detection

**Additional via `openssl s_client`:**
- OCSP stapling status
- Certificate Transparency SCT inclusion
- HPKP header detection

### 9.7 How Scan Results Are Stored

The `scan_asset_results` table stores rich JSON blobs per asset per scan:

```typescript
{
  assetId:      number;
  scanId:       number;
  ports:        PortFinding[];
  subdomains:   SubdomainFinding[];
  endpoints:    EndpointFinding[];
  dnsRecords:   DnsRecord[];
  httpInfo:     HttpInfo;
  sslCert:      SslCertInfo;
  techStack:    TechDetection[];
  screenshots:  string[];          // base64 encoded
  secretsFound: SecretMatch[];
  cloudBuckets: CloudBucketResult[];
  parameters:   string[];
  jsEndpoints:  string[];
  vulnFindings: VulnFinding[];     // from Nuclei
  intelItems:   IntelItem[];       // OSINT data
  rawOutput:    Record<string, any>;
}
```

Findings (`findings` table) are then created from `vulnFindings` and `secretsFound` arrays with full CVE enrichment.

### 9.8 Real CVE Enrichment

**`lib/nvdLookup.ts`** — two enrichment paths:

**Path A: Shodan InternetDB** (for IP assets)
```
GET https://internetdb.shodan.io/<ip>
→ Returns: { cves: ["CVE-2023-XXXX", ...], ports: [...], tags: [...] }
→ Each CVE ID then fetched from NVD for full metadata
```

**Path B: NVD CPE Lookup** (for services with version strings)
```
GET https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=<cpe>
→ Returns full CVE list for that CPE string
→ Each CVE includes: CVSS v3 score, vector, description, CWE, published date
```

NVD API key (stored in `platform_settings`) increases rate limit from 5 req/30s to 50 req/30s.

### 9.9 Scan Scheduler

**`lib/scanScheduler.ts`** — runs on server startup, checks every minute for due scans.

Scan schedule config:
- `frequency`: hourly / daily / weekly / monthly
- `targetAssetIds` or `targetGroupId`: what to scan
- `toolIds`: which tools to include
- `nextRunAt`: computed timestamp
- `isActive`: enable/disable without deleting

---

## 10. Security Tools Catalog

35+ built-in tools, auto-seeded for every tenant:

### Reconnaissance (Phase 1)

| Tool | Description | GitHub |
|---|---|---|
| **subfinder** | Passive subdomain enumeration from 40+ data sources | projectdiscovery/subfinder |
| **findomain** | CT-log-based subdomain finder | Findomain/Findomain |
| **dnsx** | DNS resolver and brute-forcer | projectdiscovery/dnsx |
| **alterx** | Subdomain permutation generator | projectdiscovery/alterx |
| **theHarvester** | Email, hostname, URL harvester from OSINT | laramies/theHarvester |
| **cloud-enum** | Cloud storage bucket enumeration | initstring/cloud_enum |
| **firebase-recon** | Firebase database exposure checker | Turr0n/firebase |
| **GrayhatWarfare** | Cloud bucket search engine | grayhatwarfare.com |

### Port Scanning (Phase 2)

| Tool | Description | GitHub |
|---|---|---|
| **naabu** | Fast port scanner | projectdiscovery/naabu |
| **masscan** | High-speed mass port scanner | robertdavidgraham/masscan |
| **rustscan** | Fast Rust-based port scanner | RustScan/RustScan |

### Web Reconnaissance (Phase 3)

| Tool | Description | GitHub |
|---|---|---|
| **httpx** | HTTP probing (status, tech, title) | projectdiscovery/httpx |
| **katana** | JS-aware web crawler | projectdiscovery/katana |
| **hakrawler** | Fast HTML link extractor | hakluke/hakrawler |
| **gau** | GetAllURLs from Wayback/CommonCrawl | lc/gau |
| **waybackurls** | Wayback Machine CDX API | tomnomnom/waybackurls |
| **feroxbuster** | Directory brute-forcer | epi052/feroxbuster |
| **wappalyzer** | Technology fingerprinting | enthec/webappanalyzer |
| **webcheck** | HTTP security header auditor | lissy93/web-check |
| **uro** | URL deduplication | s0md3v/uro |
| **paramspider** | Parameter discovery | devanshbatham/paramspider |
| **arjun** | Hidden parameter discovery | s0md3v/Arjun |
| **linkfinder** | JS endpoint extractor | GerbenJavado/LinkFinder |
| **secretfinder** | JS secret pattern scanner | m4ll0k/SecretFinder |

### Screenshots (Phase 3)

| Tool | Description |
|---|---|
| **gowitness** | Chromium-based web screenshots |
| **eyewitness** | Visual recon with server headers |
| **snapback** | Screenshot + sensitive info scanner |

### Vulnerability Scanning (Phase 4)

| Tool | Description | GitHub |
|---|---|---|
| **nuclei** | Template-based vuln scanner (40+ templates) | projectdiscovery/nuclei |
| **nikto** | Web server vulnerability scanner (6700+ checks) | sullo/nikto |
| **dalfox** | XSS scanner | hahwul/dalfox |
| **trufflehog** | Git secrets scanner | trufflesecurity/trufflehog |
| **gitdumper** | Exposed .git directory extractor | internetwache/GitTools |

### SSL/TLS (Phase 5)

| Tool | Description |
|---|---|
| **testssl.sh** | TLS/SSL configuration tester |
| **sslscan** | SSL cipher suite enumeration |

---

## 11. Multi-Tenancy Model

Every single DB query in the system is scoped by `tenantId`. This is extracted from the verified JWT on every request and attached to `req.user.tenantId`.

**Enforcement pattern (all route files):**

```typescript
router.get("/assets", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;

  // tenantId ALWAYS in the WHERE clause — no cross-tenant leakage possible
  const assets = await db
    .select()
    .from(assetsTable)
    .where(eq(assetsTable.tenantId, tenantId));

  res.json(assets);
});
```

**Tenant hierarchy:**
```
super_admin (platform-wide)
    └── tenants[]
            └── users[]
            └── assets[]
            └── findings[]
            └── scans[]
            └── compliance[]
            └── alerts[]
            └── ...
```

A `super_admin` user can query all tenants by passing `tenantId` as a query parameter. All other roles can only see their own tenant's data.

---

## 12. Frontend Architecture

### Routing

Uses `wouter` (2KB alternative to react-router) with `base` set to `import.meta.env.BASE_URL`.

Route registration in `App.tsx`:
```typescript
<Route path="/alerts/:id" component={() => <ProtectedRoute component={AlertDetailPage} />} />
```

All protected routes wrap `<AppLayout>` which renders the Sidebar + Navbar.

### State Management

| State Type | Solution |
|---|---|
| Server state (API data) | TanStack Query v5 — cache, refetch, mutation |
| Auth state (tokens, user) | Zustand store (`useAuth`) |
| UI state (modals, filters) | Local `useState` in each page component |

### Data Fetching Pattern

```typescript
// Generated hook usage (contract-first)
const { data: findings, isLoading } = useListFindings(
  { severity: "critical", status: "open" },
  { query: { queryKey: getListFindingsQueryKey({ severity: "critical" }) } }
);

// Mutation
const updateFinding = useUpdateFinding();
await updateFinding.mutateAsync({
  findingId: 1,
  data: { status: "mitigated" }
});
qc.invalidateQueries({ queryKey: getListFindingsQueryKey() });
```

### Custom Fetch (Token Injection)

`lib/custom-fetch.ts` intercepts every API request and injects the Bearer token:

```typescript
const token = sessionStorage.getItem("access_token");
if (token) {
  headers["Authorization"] = `Bearer ${token}`;
}
```

### Lazy Loading

All page components are lazy-loaded:
```typescript
const FindingsPage = lazy(() => import("@/pages/FindingsPage"));
```

This keeps the initial bundle small and defers loading until navigation.

---

## 13. Environment Variables

### Required

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string. Format: `postgresql://user:password@host:5432/dbname` |
| `SESSION_SECRET` | Secret key for JWT signing. Must be at least 32 random characters. **Never expose.** |
| `PORT` | Port the API server listens on (set by workflow, default 8080) |

### Optional (Frontend build)

| Variable | Description |
|---|---|
| `BASE_URL` | Vite base URL path for the frontend (default `/`) |

### Optional (stored in platform_settings DB, not env vars)

| Key | Description |
|---|---|
| `resend_api_key` | Resend.com API key for email delivery |
| `shodan_api_key` | Shodan API key for CVE enrichment |
| `nvd_api_key` | NVD API key for higher rate limits |
| `slack_webhook_url` | Slack notifications |
| `discord_webhook_url` | Discord notifications |
| `virustotal_api_key` | VirusTotal reputation lookups |
| `hunter_api_key` | Hunter.io email OSINT |
| `smtp_*` | Custom SMTP server settings |

---

## 14. Local Development Setup

### Prerequisites

- **Node.js** 24.x (`node --version`)
- **pnpm** 9.x (`npm install -g pnpm`)
- **PostgreSQL** 16+ running locally or via Docker

### Step 1: Clone & Install

```bash
git clone <your-repo-url> sentinelware
cd sentinelware
pnpm install
```

### Step 2: Environment Variables

Create `.env` file in the repo root (or set them in your shell):

```bash
DATABASE_URL=postgresql://postgres:password@localhost:5432/sentinelware
SESSION_SECRET=your-random-32-char-secret-here-change-this
```

### Step 3: Database Setup

```bash
# Create the database
createdb sentinelware

# Push the schema (creates all 21 tables)
pnpm --filter @workspace/db run push
```

### Step 4: Start the Servers

Open two terminals:

**Terminal 1 — API Server:**
```bash
pnpm --filter @workspace/api-server run dev
```
Builds with esbuild and starts on port 8080. Rebuild is triggered by the `dev` script on every restart.

**Terminal 2 — Frontend:**
```bash
pnpm --filter @workspace/ctem-platform run dev
```
Starts Vite dev server on port 23203 with HMR.

### Step 5: First Login

1. Navigate to `http://localhost:23203`
2. Click "Create workspace" to register a new tenant + admin user
3. Demo data is auto-seeded: 5 assets, 6 findings, risk scores, compliance controls

### Useful Commands

```bash
# Run typechecks across all packages
pnpm run typecheck

# Regenerate API hooks + Zod schemas after editing openapi.yaml
pnpm --filter @workspace/api-spec run codegen

# Push schema changes after editing lib/db/src/schema/*.ts
pnpm --filter @workspace/db run push

# Force push (drops and recreates — dev only, destroys data)
pnpm --filter @workspace/db run push-force
```

---

## 15. Production Server Installation

### 15.1 Server Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Disk | 40 GB | 100+ GB SSD |
| OS | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| Network | Static IP | Static IP + domain |

### 15.2 System Tools to Install

```bash
# Update package index
sudo apt-get update && sudo apt-get upgrade -y

# Core tools
sudo apt-get install -y \
  curl wget git unzip build-essential \
  nginx certbot python3-certbot-nginx \
  whois openssl nmap \
  postgresql postgresql-contrib \
  chromium-browser

# Node.js 24.x via NodeSource
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt-get install -y nodejs

# pnpm
npm install -g pnpm@9

# Verify
node --version    # v24.x.x
pnpm --version    # 9.x.x
psql --version    # PostgreSQL 16.x
nmap --version    # 7.x
```

#### Optional Security Tool Binaries

These are used by the scan engine. Install whichever your use case requires:

```bash
# Go-based tools (requires Go 1.21+)
sudo apt-get install -y golang-go

# subfinder
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# httpx
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# dnsx
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

# naabu
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# nuclei
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates    # download template library

# alterx
go install github.com/projectdiscovery/alterx/cmd/alterx@latest

# feroxbuster (Rust binary)
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash

# gau
go install github.com/lc/gau/v2/cmd/gau@latest

# hakrawler
go install github.com/hakluke/hakrawler@latest

# waybackurls
go install github.com/tomnomnom/waybackurls@latest

# trufflehog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# dalfox
go install github.com/hahwul/dalfox/v2@latest

# nikto (Perl-based)
sudo apt-get install -y nikto

# testssl.sh
git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl
sudo ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# Add Go binaries to PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### 15.3 Application Installation

```bash
# Create application user (no sudo)
sudo useradd -m -s /bin/bash sentinelware
sudo su - sentinelware

# Clone the repository
git clone <your-repo-url> /home/sentinelware/app
cd /home/sentinelware/app

# Install Node.js dependencies
pnpm install --frozen-lockfile
```

**Create environment file:**

```bash
cat > /home/sentinelware/app/.env << 'EOF'
DATABASE_URL=postgresql://sentinelware:CHANGE_THIS_PASSWORD@localhost:5432/sentinelware
SESSION_SECRET=CHANGE_THIS_TO_A_64_CHARACTER_RANDOM_STRING
NODE_ENV=production
EOF

chmod 600 /home/sentinelware/app/.env
```

**Build the frontend:**

```bash
cd /home/sentinelware/app
pnpm --filter @workspace/ctem-platform run build
# Output: artifacts/ctem-platform/dist/
```

**Build the API server:**

```bash
cd /home/sentinelware/app/artifacts/api-server
pnpm run build
# Output: artifacts/api-server/dist/index.mjs
```

### 15.4 Nginx Reverse Proxy

```bash
sudo nano /etc/nginx/sites-available/sentinelware
```

```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate     /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # API traffic
    location /api/ {
        proxy_pass         http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;    # long-running scans
        proxy_send_timeout 300s;
    }

    # Frontend SPA — serve from built dist
    location / {
        root   /home/sentinelware/app/artifacts/ctem-platform/dist;
        index  index.html;
        try_files $uri $uri/ /index.html;    # SPA fallback
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/sentinelware /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 15.5 Systemd Services

**API Server Service:**

```bash
sudo nano /etc/systemd/system/sentinelware-api.service
```

```ini
[Unit]
Description=Sentinelware API Server
After=network.target postgresql.service

[Service]
Type=simple
User=sentinelware
WorkingDirectory=/home/sentinelware/app/artifacts/api-server
EnvironmentFile=/home/sentinelware/app/.env
Environment=PORT=8080
Environment=NODE_ENV=production
ExecStart=/usr/bin/node --enable-source-maps ./dist/index.mjs
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinelware-api

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable sentinelware-api
sudo systemctl start sentinelware-api
sudo systemctl status sentinelware-api
```

**Check logs:**
```bash
sudo journalctl -u sentinelware-api -f
```

### 15.6 SSL with Certbot

```bash
sudo certbot --nginx -d your-domain.com
# Follow prompts, auto-renews via systemd timer
sudo systemctl status certbot.timer
```

### 15.7 PostgreSQL Setup

```bash
# Switch to postgres user
sudo -u postgres psql

-- Create database and user
CREATE USER sentinelware WITH PASSWORD 'CHANGE_THIS_PASSWORD';
CREATE DATABASE sentinelware OWNER sentinelware;
GRANT ALL PRIVILEGES ON DATABASE sentinelware TO sentinelware;
\q

# Push schema
cd /home/sentinelware/app
DATABASE_URL=postgresql://sentinelware:CHANGE_THIS_PASSWORD@localhost:5432/sentinelware \
  pnpm --filter @workspace/db run push
```

**PostgreSQL tuning for production (edit `/etc/postgresql/16/main/postgresql.conf`):**

```ini
max_connections = 100
shared_buffers = 256MB              # 25% of RAM
effective_cache_size = 1GB          # 75% of RAM
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 4MB
```

```bash
sudo systemctl restart postgresql
```

---

## 16. Operational Runbooks

### Deploy a Code Update

```bash
cd /home/sentinelware/app
git pull origin main
pnpm install --frozen-lockfile
pnpm --filter @workspace/db run push            # if schema changed
pnpm --filter @workspace/ctem-platform run build # rebuild frontend
pnpm --filter @workspace/api-server run build    # rebuild API
sudo systemctl restart sentinelware-api
```

### After Editing the OpenAPI Spec

```bash
pnpm --filter @workspace/api-spec run codegen
# This regenerates:
#   lib/api-client-react/src/generated/api.ts
#   lib/api-zod/src/generated/api.ts
# Then rebuild + redeploy
```

### Database Backup

```bash
pg_dump -U sentinelware sentinelware > backup_$(date +%Y%m%d_%H%M%S).sql
```

### Restore from Backup

```bash
psql -U sentinelware sentinelware < backup_20260101_120000.sql
```

### View API Logs

```bash
sudo journalctl -u sentinelware-api --since "1 hour ago"
```

### Rotate JWT Secret

1. Generate a new secret: `openssl rand -hex 32`
2. Update `SESSION_SECRET` in `.env`
3. Restart the API: `sudo systemctl restart sentinelware-api`
4. All existing JWT tokens are immediately invalidated — all users will be logged out

### Add a New Super Admin

```bash
# Via psql directly (first super admin before UI exists)
psql -U sentinelware sentinelware -c "
  INSERT INTO users (tenant_id, email, password_hash, role, name)
  VALUES (1, 'admin@yourcompany.com', '<bcrypt-hash>', 'super_admin', 'Admin');
"
# Generate bcrypt hash:
node -e "const b=require('bcryptjs'); b.hash('your-password', 12).then(console.log)"
```

---

## 17. Pending / Roadmap Items

### High Priority

| Item | Description |
|---|---|
| **Email delivery wiring** | Resend API key is stored in Platform Settings but email is not yet sent for invitations, password resets, or alert notifications |
| **Slack/Discord notifications** | Webhook URLs stored but alert rules don't fire real HTTP POSTs to webhooks yet |
| **NVD API key usage** | Key stored but not passed as `apiKey` header in NVD requests yet — will unlock 50 req/30s rate limit |
| **VirusTotal lookups** | API key stored; no implementation exists for domain/IP reputation |
| **Hunter.io OSINT** | API key stored; no implementation for employee email enumeration |

### Medium Priority

| Item | Description |
|---|---|
| **Compliance evidence upload** | Controls can be set pass/fail but no file attachment for evidence |
| **Report PDF/CSV export** | Reports page exists but no download/export of generated reports |
| **Real-time alerts via WebSocket** | Alerts are polled every 30s; no push delivery |
| **Bulk finding actions** | No bulk-close, bulk-assign, or bulk-export of findings |
| **Scheduled report delivery** | No automated email delivery of scheduled reports |
| **Invitation email** | Token generated in DB but no email sent to the invitee |
| **Password reset email** | Reset token generated but no email sent |

### Lower Priority

| Item | Description |
|---|---|
| **2FA / MFA** | No TOTP or WebAuthn second factor |
| **SSO / SAML** | No enterprise SSO integration |
| **Personal API tokens** | No programmatic API access for CI/CD integration |
| **Generic outbound webhooks** | No custom webhook delivery per alert rule |
| **Dark/light theme toggle** | Currently dark-only |
| **Mobile responsive layout** | Sidebar and tables not optimised for small screens |
| **Audit log export** | Can view but not download as CSV |
| **Asset map / topology view** | No visual network graph of asset relationships |

---

*End of Sentinelware CTEM Platform Documentation*
