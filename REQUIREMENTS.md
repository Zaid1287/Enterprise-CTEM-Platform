# Sentinelware CTEM Platform — Requirements

> **Version:** 1.0  
> **Last Updated:** June 2026

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Software Dependencies](#2-software-dependencies)
3. [Node.js Package Dependencies](#3-nodejs-package-dependencies)
4. [Security Tool Binaries](#4-security-tool-binaries)
5. [Environment Variables](#5-environment-variables)
6. [Network Requirements](#6-network-requirements)
7. [Database Requirements](#7-database-requirements)
8. [Browser Requirements](#8-browser-requirements)
9. [Optional / Third-Party API Keys](#9-optional--third-party-api-keys)

---

## 1. System Requirements

### Minimum (Development / Single-Tenant)

| Resource | Minimum |
|---|---|
| CPU | 2 cores (x86_64) |
| RAM | 4 GB |
| Disk | 20 GB SSD |
| OS | Ubuntu 22.04 LTS / macOS 13+ / Windows 11 WSL2 |
| Network | Outbound internet access (for NVD, Shodan, ip-api.com) |

### Recommended (Production / Multi-Tenant)

| Resource | Recommended |
|---|---|
| CPU | 4+ cores (x86_64) |
| RAM | 8+ GB |
| Disk | 100+ GB SSD (screenshots accumulate) |
| OS | Ubuntu 24.04 LTS |
| Network | Static IP, domain name, inbound 80/443 open |

---

## 2. Software Dependencies

### Required (Runtime)

| Software | Version | How to Install |
|---|---|---|
| **Node.js** | 24.x LTS | `curl -fsSL https://deb.nodesource.com/setup_24.x \| sudo bash - && sudo apt-get install -y nodejs` |
| **pnpm** | 9.x | `npm install -g pnpm@9` |
| **PostgreSQL** | 16+ | `sudo apt-get install -y postgresql postgresql-contrib` |
| **OpenSSL** | 3.x | Pre-installed on Ubuntu 22.04+ |
| **nmap** | 7.x | `sudo apt-get install -y nmap` |
| **whois** | any | `sudo apt-get install -y whois` |

### Required (Build)

| Software | Version | Notes |
|---|---|---|
| **TypeScript** | 5.9 | Installed via pnpm as devDependency |
| **esbuild** | 0.27.3 | Installed via pnpm |
| **Vite** | 7.x | Installed via pnpm |

### Required (Screenshots Feature)

| Software | Version | How to Install |
|---|---|---|
| **Chromium** | 114+ | `sudo apt-get install -y chromium-browser` |

Puppeteer (which powers the screenshot engine) uses the system Chromium install.

### Required (Production Web Server)

| Software | Version | How to Install |
|---|---|---|
| **Nginx** | 1.24+ | `sudo apt-get install -y nginx` |
| **Certbot** | 2.x | `sudo apt-get install -y certbot python3-certbot-nginx` |

---

## 3. Node.js Package Dependencies

### API Server (`artifacts/api-server`)

#### Runtime Dependencies

| Package | Version | Purpose |
|---|---|---|
| `express` | ^5.2.1 | HTTP framework |
| `jsonwebtoken` | ^9.0.3 | JWT sign/verify |
| `bcryptjs` | ^3.0.3 | Password hashing |
| `drizzle-orm` | ^0.45.2 | Type-safe ORM |
| `pg` | ^8.20.0 | PostgreSQL driver |
| `pino` | ^9.14.0 | Structured logging |
| `pino-http` | ^10.5.0 | HTTP request logging |
| `cors` | ^2.8.6 | CORS headers |
| `cookie-parser` | ^1.4.7 | Cookie parsing |
| `multer` | ^2.1.1 | Multipart file uploads |
| `puppeteer` | ^25.1.0 | Headless browser screenshots |
| `resend` | ^6.12.4 | Email delivery SDK |
| `zod` | ^3.25.76 | Runtime validation |
| `@workspace/db` | workspace | Shared DB client + schemas |
| `@workspace/api-zod` | workspace | Generated Zod schemas |

#### Dev Dependencies

| Package | Version | Purpose |
|---|---|---|
| `esbuild` | 0.27.3 | Bundle to ESM |
| `typescript` | ~5.9.3 | Type checking |
| `@types/express` | ^5.0.6 | Express types |
| `@types/jsonwebtoken` | ^9.0.10 | JWT types |
| `@types/bcryptjs` | ^3.0.0 | bcrypt types |
| `@types/cors` | ^2.8.19 | cors types |
| `@types/node` | ^25.3.3 | Node.js types |
| `pino-pretty` | ^13.1.3 | Human-readable log formatter |
| `esbuild-plugin-pino` | ^2.3.3 | esbuild pino transport plugin |

### Frontend (`artifacts/ctem-platform`)

#### Runtime Dependencies

| Package | Version | Purpose |
|---|---|---|
| `zustand` | ^5.0.14 | Global auth state |

#### Dev Dependencies (bundled into static assets)

| Package | Version | Purpose |
|---|---|---|
| `react` | 19.1.0 | UI framework |
| `react-dom` | 19.1.0 | React DOM renderer |
| `vite` | ^7.3.2 | Dev server + bundler |
| `typescript` | ~5.9.3 | Type checking |
| `tailwindcss` | ^4.1.14 | Utility CSS |
| `@tailwindcss/vite` | ^4.1.14 | Vite Tailwind plugin |
| `@tanstack/react-query` | ^5.90.21 | Server state management |
| `wouter` | ^3.3.5 | Client-side routing |
| `recharts` | ^2.15.2 | Chart components |
| `lucide-react` | ^0.545.0 | Icon set |
| `framer-motion` | ^12.23.24 | Animations |
| `date-fns` | ^3.6.0 | Date formatting |
| `zod` | ^3.25.76 | Schema validation |
| `clsx` | ^2.1.1 | Class name utility |
| `tailwind-merge` | ^3.3.1 | Tailwind class merging |
| `class-variance-authority` | ^0.7.1 | Variant-based component styles |
| `@radix-ui/react-*` | Various | Accessible UI primitives |
| `react-hook-form` | ^7.55.0 | Form state management |
| `@hookform/resolvers` | ^3.10.0 | Zod + react-hook-form bridge |
| `vaul` | ^1.1.2 | Drawer component |
| `cmdk` | ^1.1.1 | Command palette |
| `sonner` | ^2.0.7 | Toast notifications |
| `embla-carousel-react` | ^8.6.0 | Carousel component |
| `react-resizable-panels` | ^2.1.7 | Resizable panel layouts |
| `react-icons` | ^5.4.0 | Additional icon sets |
| `react-day-picker` | ^9.11.1 | Date picker |
| `input-otp` | ^1.4.2 | OTP input component |
| `next-themes` | ^0.4.6 | Theme management |
| `@workspace/api-client-react` | workspace | Generated React Query hooks |

### Database Library (`lib/db`)

| Package | Version | Purpose |
|---|---|---|
| `drizzle-orm` | ^0.45.2 | ORM core |
| `drizzle-zod` | ^0.8.3 | Auto-generate Zod from Drizzle |
| `pg` | ^8.20.0 | PostgreSQL driver |
| `zod` | ^3.25.76 | Schema validation |
| `drizzle-kit` | ^0.31.10 | Schema push / migrations (dev) |

### API Spec / Codegen (`lib/api-spec`)

| Package | Version | Purpose |
|---|---|---|
| `orval` | (via config) | OpenAPI → React Query + Zod codegen |

---

## 4. Security Tool Binaries

These are **not** npm packages. They are standalone binaries used by the scan engine at runtime. Install those you want to enable:

### Essential (used in base scan)

| Tool | Language | Install |
|---|---|---|
| `nmap` | C | `sudo apt-get install -y nmap` |
| `whois` | C | `sudo apt-get install -y whois` |
| `openssl` | C | Pre-installed (Ubuntu) |

### Subdomain Enumeration

| Tool | Language | Install |
|---|---|---|
| `subfinder` | Go | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `findomain` | Rust | Download from https://github.com/Findomain/Findomain/releases |
| `dnsx` | Go | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| `alterx` | Go | `go install github.com/projectdiscovery/alterx/cmd/alterx@latest` |

### Port Scanning

| Tool | Language | Install |
|---|---|---|
| `naabu` | Go | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| `masscan` | C | `sudo apt-get install -y masscan` |
| `rustscan` | Rust | `cargo install rustscan` |

### HTTP / Web Recon

| Tool | Language | Install |
|---|---|---|
| `httpx` | Go | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `katana` | Go | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `hakrawler` | Go | `go install github.com/hakluke/hakrawler@latest` |
| `gau` | Go | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `waybackurls` | Go | `go install github.com/tomnomnom/waybackurls@latest` |
| `feroxbuster` | Rust | `curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh \| bash` |
| `uro` | Python | `pip install uro` |
| `paramspider` | Python | `pip install paramspider` |
| `arjun` | Python | `pip install arjun` |
| `nikto` | Perl | `sudo apt-get install -y nikto` |
| `dalfox` | Go | `go install github.com/hahwul/dalfox/v2@latest` |

### JavaScript Analysis

| Tool | Language | Install |
|---|---|---|
| `linkfinder` | Python | `git clone https://github.com/GerbenJavado/LinkFinder && pip install -r requirements.txt` |
| `secretfinder` | Python | `git clone https://github.com/m4ll0k/SecretFinder && pip install -r requirements.txt` |

### Vulnerability Scanning

| Tool | Language | Install |
|---|---|---|
| `nuclei` | Go | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates` |

### Screenshots

| Tool | Language | Install |
|---|---|---|
| `gowitness` | Go | `go install github.com/sensepost/gowitness@latest` |
| `eyewitness` | Python | `git clone https://github.com/RedSiege/EyeWitness` |

### Secrets Hunting

| Tool | Language | Install |
|---|---|---|
| `trufflehog` | Go | `curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \| sh -s -- -b /usr/local/bin` |

### Cloud Recon

| Tool | Language | Install |
|---|---|---|
| `cloud-enum` | Python | `git clone https://github.com/initstring/cloud_enum && pip install -r requirements.txt` |

### SSL/TLS

| Tool | Shell | Install |
|---|---|---|
| `testssl.sh` | Bash | `git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh` |
| `sslscan` | C | `sudo apt-get install -y sslscan` |

### Prerequisites for Go tools

```bash
sudo apt-get install -y golang-go
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
go version   # go1.21+
```

### Prerequisites for Python tools

```bash
sudo apt-get install -y python3 python3-pip
pip install requests beautifulsoup4 jsbeautifier
```

---

## 5. Environment Variables

### Required — Application will not start without these

| Variable | Type | Example | Description |
|---|---|---|---|
| `DATABASE_URL` | string | `postgresql://user:pass@localhost:5432/sentinelware` | Full PostgreSQL connection URL |
| `SESSION_SECRET` | string | `a8f3e2...` (64 chars) | JWT signing secret — must be random, kept secret |
| `PORT` | number | `8080` | Port API server binds to |

### Generation Commands

```bash
# Generate a secure SESSION_SECRET
openssl rand -hex 32

# Or via Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

---

## 6. Network Requirements

### Inbound (Production Server)

| Port | Protocol | Required | Purpose |
|---|---|---|---|
| 80 | TCP | Yes | HTTP → HTTPS redirect |
| 443 | TCP | Yes | HTTPS (Nginx) |
| 22 | TCP | Recommended | SSH admin access |

> Internal ports 8080 (API) and 23203 (Vite dev) should NOT be exposed. They are accessed via Nginx proxy.

### Outbound (Scan Engine)

The scan engine makes outbound connections during scans:

| Destination | Port | Protocol | Purpose |
|---|---|---|---|
| Target assets | 80, 443 | TCP | HTTP/HTTPS probing |
| Target assets | Any | TCP | Port scanning (nmap) |
| `services.nvd.nist.gov` | 443 | HTTPS | CVE data lookup |
| `internetdb.shodan.io` | 443 | HTTPS | IP CVE enrichment |
| `ip-api.com` | 443 | HTTPS | Geolocation |
| `web.archive.org` | 443 | HTTPS | Wayback Machine URL harvest |
| `index.commoncrawl.org` | 443 | HTTPS | CommonCrawl URL harvest |
| `otx.alienvault.com` | 443 | HTTPS | OTX URL harvest |

### Firewall Rules (UFW)

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status
```

---

## 7. Database Requirements

| Requirement | Value |
|---|---|
| Engine | PostgreSQL |
| Minimum version | 16 |
| Database name | `sentinelware` (configurable via `DATABASE_URL`) |
| Required extensions | None (uses only standard SQL) |
| Recommended max connections | 100 |
| Estimated disk growth | ~500 MB/month per active tenant (scan results, screenshots) |

### Tables Created by `pnpm --filter @workspace/db run push`

```
tenants
users
assets
asset_groups
scans
scan_asset_results
findings
risk_scores
compliance
alerts
audit_logs
reports
security_tools
tool_pipeline_steps
scan_schedules
packages
takedown_requests
account_manager_clients
invitations
user_ai_settings
technology_detections
screenshots
platform_settings
```

---

## 8. Browser Requirements

The frontend SPA requires a modern browser with:

| Feature | Required |
|---|---|
| ES2022+ JavaScript | Yes |
| CSS Grid + Flexbox | Yes |
| Web Crypto API | Yes (JWT parsing) |
| sessionStorage | Yes (token storage) |
| Fetch API | Yes |

### Tested Browsers

| Browser | Minimum Version |
|---|---|
| Chrome / Chromium | 114+ |
| Firefox | 115+ |
| Safari | 16+ |
| Edge | 114+ |

---

## 9. Optional / Third-Party API Keys

These are stored in the `platform_settings` DB table via the Platform Settings page (super_admin only). None are required for the platform to function — they enhance specific features.

| Key | Service | Free Tier | Purpose | Impact if Missing |
|---|---|---|---|---|
| `nvd_api_key` | NIST NVD | Free registration | CVE lookup | Rate limited to 5 req/30s (slow scans) |
| `shodan_api_key` | Shodan | Paid | IP CVE enrichment, port data | No Shodan CVE data; NVD-only enrichment |
| `resend_api_key` | Resend.com | 3,000 emails/mo free | Email notifications, invites | No emails sent |
| `smtp_*` | Any SMTP | — | Alternative to Resend | No emails sent (if Resend also absent) |
| `slack_webhook_url` | Slack | Free | Alert notifications to Slack | No Slack messages |
| `discord_webhook_url` | Discord | Free | Alert notifications to Discord | No Discord messages |
| `virustotal_api_key` | VirusTotal | 500 lookups/day free | Domain/IP reputation | No reputation lookups |
| `hunter_api_key` | Hunter.io | 25 searches/mo free | Employee email OSINT | No email enumeration |

### Obtaining API Keys

**NVD API Key:**
- Register at https://nvd.nist.gov/developers/request-an-api-key
- Free, no credit card required
- Increases rate limit to 50 req/30s

**Shodan API Key:**
- Register at https://account.shodan.io/register
- Free tier: limited queries
- Paid: full InternetDB + CVE data

**Resend API Key:**
- Register at https://resend.com
- Free tier: 3,000 emails/month, 100/day
- Add and verify your sending domain

**Shodan Free Tier Setup:**
```bash
# Test your Shodan key
curl "https://api.shodan.io/api-info?key=YOUR_KEY"
```

**NVD Rate Limit Test:**
```bash
# Without key (5 req/30s)
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=apache"

# With key (50 req/30s)
curl -H "apiKey: YOUR_NVD_KEY" "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=apache"
```

---

*End of Sentinelware CTEM Platform Requirements*
