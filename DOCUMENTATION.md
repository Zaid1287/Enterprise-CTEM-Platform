# Sentinelware CTEM Platform — Complete Technical Documentation

> **Version:** 2.0  
> **Last Updated:** June 18, 2026  
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
   - 8.21 Brand Threat Detection
   - 8.22 Attack Surface Graph / Topology
   - 8.23 Queue Monitor
   - 8.24 Session Management
   - 8.25 Exposure Management
   - 8.26 Two-Factor Authentication (2FA)
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
│                 REVERSE PROXY (Nginx / Replit)                  │
│         /          → port 23203   (React SPA / Vite)            │
│         /api       → port 8080    (Express API)                 │
└────────────────────┬────────────────────┬───────────────────────┘
                     │                    │
          ┌──────────▼──────┐   ┌─────────▼────────────────────┐
          │  Frontend (Vite) │   │  API Server (Express 5 + TS) │
          │  React 19 + TS   │   │  Port: 8080                  │
          │  Port: 23203     │   │                              │
          └──────────────────┘   │  Middleware stack:           │
                                 │  Helmet → CORS → JSON →      │
                                 │  Auth rate limiter →         │
                                 │  Global rate limiter →       │
                                 │  requireAuth → Routes        │
                                 └─────────┬────────────────────┘
                                           │
                    ┌──────────────────────┼──────────────────────┐
                    │                      │                      │
          ┌─────────▼─────────┐  ┌────────▼────────┐  ┌─────────▼────────┐
          │  PostgreSQL DB     │  │  Background      │  │  External APIs   │
          │  Drizzle ORM       │  │  Workers         │  │                  │
          │  30+ tables        │  │                  │  │  NVD, Shodan,    │
          │  RLS on all        │  │  beatScheduler   │  │  Censys, IntelX, │
          │  tenant tables     │  │  scanWorker      │  │  VirusTotal,     │
          └───────────────────┘  │  alertWorker     │  │  Hunter.io,      │
                                 │  SSE manager     │  │  crt.sh, CISA    │
                                 └─────────────────┘  └──────────────────┘
```

### Background Worker Architecture

```
API Server startup (index.ts)
  │
  ├── initBeatScheduler()        ← beatScheduler.ts
  │     ├── Every 60s: dispatchDueSchedules()
  │     │     └── SELECT scan_schedules WHERE nextRunAt <= NOW()
  │     │           └── enqueueOrRun(assetId) → pipelineScans
  │     └── Every 60s: asset-frequency dispatch
  │           └── SELECT assets WHERE nextScanAt <= NOW()
  │                 └── enqueueOrRun(assetId)
  │
  ├── initScanWorker()           ← scanWorker.ts
  │     └── BullMQ queue (Redis) or in-process queue fallback
  │         MAX_CONCURRENT_SCANS = 5
  │         MAX_PARALLEL_ASSETS  = 3
  │         3-attempt retry with exponential backoff (5s→10s→20s)
  │
  └── initAlertWorker()          ← alertWorker.ts
        └── Processes notification dispatch jobs
              └── Email / Slack / Discord / Telegram / Webhook / SSE
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

All 30+ tables and their purpose:

### Core / Auth Tables

| Table | Key Columns | Purpose |
|---|---|---|
| `tenants` | id, name, domain, plan, stripeCustomerId | One row per organisation. All data scoped by `tenant_id`. |
| `users` | id, tenantId, email, passwordHash, role, twoFactorEnabled, avatarUrl | Roles: `super_admin`, `admin`, `manager`, `client`. bcrypt hash (cost 12). |
| `sessions` | id, userId, tenantId, tokenHash, userAgent, ip, expiresAt | SHA-256 of access token. Used for session listing and revocation. |
| `invitations` | id, tenantId, email, role, token, expiresAt | Pre-registration invite tokens. Email sent on creation. |

### Asset Tables

| Table | Key Columns | Purpose |
|---|---|---|
| `assets` | id, tenantId, name, type, domain, ip, url, status, verificationStatus, riskLevel, businessImpact (1–10), tags[], lastScannedAt | All internet-facing assets. businessImpact factored into risk score. |
| `asset_groups` | id, tenantId, name, description | Named logical groups for bulk scanning and reporting. |
| `asset_group_members` | groupId, assetId | Join table linking assets to groups. |
| `technology_detections` | id, tenantId, assetId, scanId, name, category, version, confidence | Per-scan technology fingerprints. Replaced on every scan. |
| `screenshots` | id, tenantId, assetId, scanId, url, data (base64 PNG), title, statusCode | Stored as base64. No MinIO dependency. |
| `discovery_results` | id, tenantId, assetId, source, data (jsonb), createdAt | Historical passive discovery output per source. |

### Scan Tables

| Table | Key Columns | Purpose |
|---|---|---|
| `scans` | id, tenantId, assetId, status, type, startedAt, completedAt | One row per scan session. Statuses: pending/running/completed/failed/cancelled. |
| `scan_jobs` | id, scanId, assetId, tenantId, status, result | Per-asset job within a scan. |
| `scan_asset_results` | id, scanId, assetId, tenantId, raw (jsonb) | Full raw pipeline output including ports, subdomains, DNS, endpoints, SSL, CVEs. |
| `scan_schedules` | id, tenantId, assetId, frequency, nextRunAt, lastRunAt, isActive | Recurring scan schedule. Dispatched by beatScheduler every 60s. |
| `security_tools` | id, tenantId, name, category, installCommand, runCommand, outputFormat | Tool registry — 40+ built-in tools. |
| `tool_pipeline_steps` | id, tenantId, toolName, phase, isEnabled, order | Which tools run in which order per tenant. |
| `tool_runs` | id, tenantId, toolName, assetId, scanId, status, output, exitCode, startedAt | Tool execution history with real stdout/stderr. |

### Vulnerability Tables

| Table | Key Columns | Purpose |
|---|---|---|
| `findings` | id, tenantId, assetId, scanId, title, severity, status, cveId, cvss, epss, cwe, isKev, description, remediation | status: open/in_progress/accepted_risk/false_positive/mitigated. |
| `finding_comments` | id, findingId, tenantId, userId, text, createdAt | Threaded comments on findings. |

### Compliance Tables

| Table | Key Columns | Purpose |
|---|---|---|
| `compliance_frameworks` | id, tenantId, name, version | ISO 27001, SOC 2, PCI DSS, HIPAA, CIS Controls. |
| `compliance_controls` | id, tenantId, frameworkId, controlId, title, status, evidence (json-encoded file list), assignee, dueDate | evidence stores filenames; files served via `/compliance/controls/:id/evidence/:filename`. |

### Risk Tables

| Table | Key Columns | Purpose |
|---|---|---|
| `risk_scores` | id, tenantId, assetId, score, level, factors (jsonb), calculatedAt | Multi-factor: CVSS + EPSS + KEV + criticality + exposure + businessImpact. |

### Alerting Tables

| Table | Key Columns | Purpose |
|---|---|---|
| `alerts` | id, tenantId, title, severity, type, assetId, findingId, status, seenAt | Triggered on scan events. Delivered via SSE stream. |
| `alert_rules` | id, tenantId, name, triggerType, channel, channelConfig (jsonb), isActive | channelConfig holds webhook URL, Telegram chatId, etc. |

### Reporting Tables

| Table | Key Columns | Purpose |
|---|---|---|
| `reports` | id, tenantId, title, type, format, status, filePath, createdAt | type: executive/technical/compliance/inventory. |

### Brand Threat Tables

| Table | Key Columns | Purpose |
|---|---|---|
| `brand_threat_scans` | id, tenantId, brandName, status, permutationCount | One per brand threat scan run. |
| `brand_threat_results` | id, scanId, tenantId, domain, type, risk, registrar, registeredAt | Individual suspicious domain results. |
| `takedown_requests` | id, tenantId, domain, brandScanResultId, status, reason, notes | Formal takedown workflow for malicious domains. |

### Platform / Admin Tables

| Table | Key Columns | Purpose |
|---|---|---|
| `audit_logs` | id, tenantId, userId, action, resourceType, resourceId, metadata, ip, createdAt | **Immutable** — PostgreSQL trigger blocks all UPDATE/DELETE. |
| `platform_settings` | id, tenantId, key, value | Tenant-scoped key-value store for API keys and config. |
| `user_ai_settings` | id, userId, tenantId, provider, apiKey, model, systemPrompt | Per-user LLM preferences. |
| `packages` | id, tenantId, name, price, features, maxAssets, maxUsers | Pricing tiers for the SaaS product. |
| `account_manager_clients` | managerId, clientId, tenantId | Account manager ↔ client organization assignments. |

### Key Relationships

```
tenants ──< users ──< sessions
tenants ──< assets ──< scan_asset_results >── scans
                   ──< findings ──< finding_comments
                   ──< technology_detections
                   ──< screenshots
                   ──< discovery_results
                   ──< risk_scores
tenants ──< compliance_frameworks ──< compliance_controls
tenants ──< alerts
tenants ──< alert_rules
tenants ──< security_tools ──< tool_pipeline_steps
                           ──< tool_runs
tenants ──< brand_threat_scans ──< brand_threat_results ──< takedown_requests
tenants ──< reports
tenants ──< audit_logs
tenants ──< platform_settings
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

Risk score calculation per asset — multi-factor, NOT only CVSS:

```
Asset Risk Score = Σ (finding.cvss × epssWeight × kevMultiplier)
                  + exposurePenalty (dangerous exposed ports)
                  + (businessImpact / 10) × 20

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
**Engine:** `lib/notifier.ts`

**Alert Channels (all fully implemented):**

| Channel | Delivery Method | Config Required |
|---|---|---|
| **Email** | Resend API (HTML template) | `resend_api_key` in Platform Settings |
| **Slack** | Block Kit formatted webhook POST | `slack_webhook_url` per alert rule |
| **Discord** | Embed webhook POST | `discord_webhook_url` per alert rule |
| **Telegram** | Bot API `sendMessage` (HTML parse mode) | `telegram_bot_token` + `telegram_chat_id` per alert rule |
| **Webhook (Generic)** | Raw JSON POST to any URL | Webhook URL per alert rule |
| **SSE (Browser)** | Server-Sent Events stream | Built-in — no config needed |

**Alert Trigger Types (fired from `dispatchNotifications()`):**

| Trigger | When It Fires |
|---|---|
| `scan_complete` | Every scan finishes (success or failure) |
| `critical_finding` | Scan results contain one or more critical-severity findings |
| `high_finding` | Scan results contain high or critical findings |
| `new_finding` | Any finding discovered during a scan |
| `brand_threat` | Brand threat scan completes with suspicious domains found |

> **Note:** `new_asset`, `ssl_expiry`, and `compliance_failure` are selectable in the UI alert rule builder but are not yet auto-dispatched — see Section 17.

**Alert Rules:** Configurable per-tenant rules that map trigger types to channels. Multiple rules can target the same trigger. Each rule has its own `channelConfig` JSON (webhook URL, Telegram chatId, etc.).

**Real-time delivery:** `GET /alerts/stream` returns a persistent SSE connection. The browser receives new alerts instantly without polling. `sseManager.ts` holds active connections by userId and pushes on every `dispatchNotifications()` call.

**Alert Detail Page (`/alerts/:id`):** Full alert message, severity badge, type, timestamp, auto-marks read on load, deep links to related asset or finding.

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
| `resend_api_key` | Email | Resend.com API key for transactional email alerts and invitations |
| `smtp_host` / `smtp_port` / `smtp_user` / `smtp_pass` / `smtp_from` | Email | Custom SMTP server as alternative to Resend |
| `slack_webhook_url` | Notifications | Slack incoming webhook for default Slack alerts |
| `discord_webhook_url` | Notifications | Discord webhook for default Discord alerts |
| `telegram_bot_token` | Notifications | Telegram Bot API token |
| `telegram_chat_id` | Notifications | Default Telegram chat/channel ID |
| `shodan_api_key` | Scanning | Full Shodan API — CVE enrichment, CPEs, banner data, port history |
| `nvd_api_key` | Scanning | NVD rate limit: 5 req/30s (no key) → 50 req/30s (with key) |
| `virustotal_api_key` | Scanning | Domain/IP reputation + passive DNS lookups |
| `hunter_api_key` | OSINT | Employee email enumeration via Hunter.io |
| `censys_api_id` / `censys_api_secret` | OSINT | Censys internet-wide scan data |
| `intelx_api_key` | OSINT | IntelligenceX historical data, darkweb, pastes |
| `github_token` | OSINT | GitHub secret scanning — authenticated = higher rate limits |
| `fofa_email` / `fofa_api_key` | OSINT | Fofa.info internet exposure search |
| `criminalip_api_key` | OSINT | CriminalIP threat intelligence lookups |
| `nvd_api_key` | Vuln | NVD API key for enhanced CVE enrichment rate |
| `stripe_secret_key` | Billing | Stripe payments integration |
| `stripe_webhook_secret` | Billing | Stripe webhook signature verification |

Values are masked in the UI. The "reveal" button fetches the real value from `/platform/settings/raw/:key`.

---

### 8.21 Brand Threat Detection

**Page:** `/brand-threats`, `/brand-threats/:id`  
**Route file:** `routes/brandThreats.ts`  
**Engine:** `lib/brandThreatRunner.ts`

Detects typosquatting, phishing domains, and brand impersonation:

**How it works:**
1. Takes the brand name and generates 4,000+ domain permutations using dnstwist-style algorithms (homoglyphs, transpositions, vowel swaps, hyphen insertion, TLD variations, bit-flipping)
2. Resolves each permutation — marks registered ones as suspicious
3. Captures favicons from suspicious domains and compares favicon hashes (favihunter integration)
4. Assigns risk levels: Critical / High / Medium / Low
5. Screenshots suspicious domains
6. Fires `brand_threat` alert rule if high-risk domains found

**Result fields:** domain, permutation type, registration status, registrar, registration date, risk level, favicon hash match, screenshot.

**Takedown integration:** Each brand threat result can be escalated to a Takedown Request directly from the detail page.

---

### 8.22 Attack Surface Graph / Topology

**Page:** `/topology`  
**Route file:** `routes/graph.ts`  
**Engine:** `GET /graph/attack-surface`

Visual force-directed graph of the organisation's attack surface.

**Graph data format (Neo4j-style):**
```json
{
  "nodes": [
    { "id": "org-1",    "type": "organization", "label": "Example Corp" },
    { "id": "asset-42", "type": "asset",         "label": "example.com" },
    { "id": "port-443", "type": "port",          "label": "443/HTTPS" },
    { "id": "finding-7","type": "finding",       "label": "CVE-2024-1234" },
    { "id": "cve-1234", "type": "cve",           "label": "CVE-2024-1234" }
  ],
  "relationships": [
    { "source": "org-1",    "target": "asset-42", "type": "OWNS" },
    { "source": "asset-42", "target": "port-443", "type": "EXPOSES" },
    { "source": "asset-42", "target": "finding-7","type": "HAS_VULNERABILITY" },
    { "source": "finding-7","target": "cve-1234", "type": "REFERENCES_CVE" }
  ]
}
```

**Relationship types:** `OWNS`, `SUBDOMAIN_OF`, `RESOLVES_TO`, `EXPOSES`, `HAS_VULNERABILITY`, `REFERENCES_CVE`

**Frontend:** D3.js force simulation with zoom, pan, drag, and click-through to asset/finding detail pages. Node colour-coded by type. Neo4j-ready — data format is compatible with a future Neo4j integration.

---

### 8.23 Queue Monitor

**Page:** `/queue-monitor`  
**Route file:** `routes/queues.ts`  
**Access:** `super_admin` only

Displays BullMQ queue metrics:
- Active / waiting / completed / failed job counts
- Per-queue breakdown (scan-queue, alert-queue)
- Job list with status, payload preview, timestamps
- Manual retry of failed jobs

When Redis is unavailable, shows in-process queue state instead.

---

### 8.24 Session Management

**Page:** `/settings/account` (Sessions tab)  
**Route file:** `routes/sessions.ts`

Every login creates a `sessions` row with:
- `tokenHash` — SHA-256 of the access token (never stores the raw token)
- `userAgent` — parsed browser/OS from User-Agent header
- `ip` — client IP from `X-Forwarded-For` or `req.socket.remoteAddress`
- `expiresAt` — matches refresh token TTL (7 days)

Users can view all active sessions and revoke any individual session from Account Settings. Revoking a session invalidates the corresponding refresh token, forcing logout on that device.

---

### 8.25 Exposure Management

**Page:** `/exposure`  
**Powered by:** `pipelineScans.ts` DANGER port map + `nucleiScanner.ts`

Detects and catalogues exposed services that should not be internet-facing:

**Exposed ports that generate findings (26 ports):**

| Port | Service | Risk |
|---|---|---|
| 21 | FTP | High — unencrypted file transfer |
| 23 | Telnet | Critical — plaintext remote access |
| 139 | NetBIOS | Critical — Windows file sharing |
| 161 | SNMP | High — network management data |
| 389 | LDAP | High — directory service |
| 445 | SMB | Critical — EternalBlue/ransomware target |
| 1433 | MSSQL | Critical — database exposed |
| 1521 | Oracle DB | Critical — database exposed |
| 2375/2376 | Docker API | Critical — container escape risk |
| 2379 | etcd | Critical — Kubernetes config store |
| 3306 | MySQL | Critical — database exposed |
| 3389 | RDP | Critical — remote desktop brute-force target |
| 5432 | PostgreSQL | Critical — database exposed |
| 5900 | VNC | Critical — remote desktop |
| 6379 | Redis | Critical — no auth by default |
| 8080/8443 | HTTP Alt | Medium — admin panels |
| 9200/9300 | Elasticsearch | Critical — full data exposure |
| 27017 | MongoDB | Critical — no auth by default |
| 50000 | SAP | High — enterprise system |

**Admin panel exposure (via Nuclei templates):** Jenkins, Grafana, Kibana, phpMyAdmin, Adminer, cPanel, Plesk, WHM, Traefik, Portainer, and 30+ others.

---

### 8.26 Two-Factor Authentication (2FA)

**Route file:** `routes/auth.ts` (2FA endpoints)  
**Page:** `/settings/account` (Security tab)

Email OTP-based 2FA flow:

```
Enable 2FA:
  POST /auth/2fa/enable   → generates OTP, sends to email
  POST /auth/2fa/confirm  → validates OTP, marks twoFactorEnabled=true in DB

Login with 2FA active:
  POST /auth/login        → 200 OK but with { requires2fa: true }
  POST /auth/2fa/verify   → validates OTP, issues full JWT tokens

Disable 2FA:
  POST /auth/2fa/disable  → validates OTP, clears twoFactorEnabled
```

OTP codes are 6-digit numeric, expire in 10 minutes, stored temporarily in the users table. Email delivery via Resend (`resend_api_key` required).

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

> Items previously listed here that are now **complete** (removed from pending):
> Email delivery ✅ · Slack/Discord notifications ✅ · NVD API key rate-limit fix ✅ · VirusTotal lookups ✅ · Hunter.io OSINT ✅ · Compliance evidence upload/download/delete ✅ · Report PDF/CSV/JSON export ✅ · Real-time SSE alerts ✅ · Password reset email ✅ · Invitation email ✅ · 2FA email OTP ✅ · Asset topology graph ✅ · Telegram + Webhook alert channels ✅ · businessImpact in risk engine ✅ · Session management ✅ · Brand Threat Detection ✅ · Takedown Requests ✅ · Security Tools real execution ✅

---

### Not Started (Requires New Development)

| Item | Priority | Description |
|---|---|---|
| **Module 8 — Go Agent** | High | The entire internal agent system was never built. Requires a Go binary (Windows/Linux/macOS) that collects host info, installed software, running processes, open ports, and patch levels, then securely communicates with the API. Needs a new `agents` DB table, registration endpoint, and token-based auth. |
| **XLSX report export** | Medium | Reports page supports PDF, CSV, JSON. Excel (`.xlsx`) format not implemented. Would require `exceljs` or similar on the backend. |
| **Custom cron expressions** | Medium | Scan scheduling supports hourly/daily/weekly/monthly. No support for arbitrary cron syntax (e.g. `0 */6 * * *`). Would require `cron-parser` library and updates to `beatScheduler.ts` and `scan_schedules` schema. |
| **API version prefix `/api/v1/`** | Low | All routes use `/api/` without versioning. A breaking change to add versioning requires updating the OpenAPI spec, all frontend hooks, and the Nginx/proxy config simultaneously. |
| **DB table partitioning** | Low | No partitioning strategy on `findings` or `audit_logs`. Required at scale (millions of rows). Would use PostgreSQL range partitioning by `created_at`. |
| **SSO / SAML** | Low | No enterprise SSO. Would require `passport-saml` or an external IdP integration (Okta, Azure AD). |
| **Personal API tokens** | Low | No programmatic API access. CI/CD pipelines cannot trigger scans or query findings without a browser session. Needs a `api_tokens` table and a separate auth path. |

---

### Partially Implemented (Needs Completion)

| Item | Status | What's Missing |
|---|---|---|
| **3 alert triggers not wired** | UI exists, backend missing | `new_asset` — no dispatch when an asset is created. `ssl_expiry` — no scheduled SSL cert expiry check. `compliance_failure` — no event fired when control status changes. These require calling `dispatchNotifications()` from the respective create/update handlers. |
| **Finding evidence file uploads** | Compliance has it, Findings don't | Findings support comments but not file attachments. Compliance controls have full evidence upload/download/delete. Findings need the same pattern. |
| **Cloud account verification** | Basic only | DNS TXT, Email, HTTP file verification are fully implemented. Cloud verification (`cloud` asset type) is implemented at the API level but does not integrate with AWS/Azure/GCP IAM APIs to confirm account ownership. |
| **Reverse WHOIS** | Basic only | WHOIS lookups are implemented. Reverse WHOIS (find all domains registered by the same org) has no dedicated service integration — no DomainTools, WhoisXML API, or SecurityTrails call. |
| **Platform analytics (Super Admin)** | Queue monitor only | Super admins can view the queue monitor. No dedicated cross-tenant analytics dashboard (total users, scan volumes, revenue, tenant health). |
| **Docker / containerisation** | Not done | No Dockerfiles or Docker Compose in the repo. Deployment runs on Replit workflows. A production Docker setup would need multi-stage Dockerfiles for API + frontend + Nginx, plus a compose file for the full stack. |
| **Redis as required service** | Optional fallback | Redis is optional. When `REDIS_URL` is not set, the platform uses an in-memory queue. For production multi-instance deployments, Redis must be required to share job state across processes. |
| **Separate RBAC permissions table** | Role column only | Role is a string column on the `users` table. There is no fine-grained permissions table. All access control is code-level via `requireRole()`. For enterprise deployments, a `permissions` table with per-resource ACLs would be needed. |

---

### Known Limitations

| Limitation | Impact | Notes |
|---|---|---|
| Screenshots stored as base64 in PostgreSQL | DB size grows large with many assets | MinIO was the original spec target. At 100+ assets with 5 screenshots each, the `screenshots` table can reach several GB. Offloading to S3/MinIO is a future migration. |
| Gowitness not used | Minor | Puppeteer/Chromium used instead. Same quality output, easier to install. Functionally equivalent. |
| OpenSearch not used | Minor for current scale | PostgreSQL `tsvector` full-text search implemented instead. Sufficient for single-tenant or small multi-tenant deployments. At millions of documents, OpenSearch would be needed for better search performance and faceting. |
| tenant_id is integer, not UUID | Schema decision | Original spec required UUID tenant IDs. Integer was used. Not a functional issue but would require a schema migration to change. |
| No DB partitioning | Risk at scale | `findings` and `audit_logs` tables grow unbounded. No partitioning by date range. At millions of rows, query performance will degrade without partitioning. |
| In-process queue fallback | Single-instance only | Without Redis, the scan queue lives in Node.js memory. If the API server restarts mid-scan, the queue state is lost. For production, Redis must be configured. |

---

*End of Sentinelware CTEM Platform Documentation — Version 2.0, June 18, 2026*
