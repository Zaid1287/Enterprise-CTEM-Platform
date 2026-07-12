---
name: TPRM role-based access model
description: How the 3-role TPRM access model is implemented — always-on for admin/SA/AM, per-tenant gated for clients
---

## Rule

Three roles, three access levels:

| Role | Module gate | Data scope |
|---|---|---|
| `super_admin` / `admin` | Always active (bypass `requireTprm`, `GET /tprm/module` returns `isEnabled:true`) | All tenants — `getVendorScopeTenantIds` queries all rows from `tenantsTable` |
| `account_manager` | Always active (same bypass) | Assigned client tenants only — `getVendorScopeTenantIds` calls `getAmClientTenantIds(userId)` |
| `client` (and others) | Gated by `tprmModuleAssignmentsTable.isEnabled` for own tenant | Own tenant only |

## Key helpers in tprm.ts

- `getVendorScopeTenantIds(req)` — returns `number[]` of tenant IDs for vendor queries; use with `inArray(tprmVendorsTable.tenantId, ids)` or `undefined` (no filter) for admin/SA.
- `resolveVendorForRole(vendorId, req)` — resolves a single vendor cross-tenant for admin/SA, within assigned clients for AM, within own-or-global for client.

## Frontend

- `TprmBootstrap` (App.tsx): admin/SA/AM sets `tprmEnabled = true` immediately without an API call; client fetches `/api/tprm/module`.
- `TprmRoute` (App.tsx): `isPrivileged` = `admin || super_admin || account_manager` — these roles skip the upgrade-page gate.
- `Sidebar.tsx`: `tprmVisible = tprmEnabled || admin || SA || AM`.

## AM vendor list extra field

`GET /tprm/vendors` response includes `tprmEnabled: boolean` per vendor (derived from `tprmModuleAssignmentsTable` for the vendor's tenant) so the frontend can render a "TPRM inactive" badge for vendors belonging to clients where the module is off.

**Why:** AM needs to see ALL their assigned clients' vendors (including ones where TPRM is disabled) so they have visibility into what's configured, while the badge communicates the disabled state. Admin/SA always get `tprmEnabled: true` on every vendor.

**How to apply:** Any new TPRM read endpoint that filters by tenant must call `getVendorScopeTenantIds(req)` and build its `inArray(...)` condition from the result. Always guard against empty array with `ids.length > 0 ? inArray(...) : sql\`false\`` (or `undefined` for no-filter case). Vendor write endpoints (PATCH, DELETE) should still enforce ownership via `resolveVendorForRole` before mutating.

## Scan + enrichment patterns

- **Bulk scan**: `POST /tprm/vendors/bulk-scan` — must be registered BEFORE `/tprm/vendors/:id` routes. Stagger individual scans by 3 s setTimeout to avoid OOM.
- **Enrichment chain**: Brandfetch → Clearbit autocomplete → HTTP homepage `<title>`/`og:site_name` scrape → DNS MX fallback. Source field is "brandfetch"/"clearbit"/"homepage"/"dns".
- **Supply chain auto-population**: `runFullVendorScan` in tprmEnrichment.ts auto-writes `tprm_supply_chain_nodes` from scan probe (IPs→infra, subdomains→saas) AND 4th party signals (cdn/hosting→infra, rest→saas). Existing SBOM-upload nodes kept via `isNull(sbomUploadId)` filter on delete.
- **Questionnaire scoring**: `score = null` (not 50) when `totalWeight === 0` (all-text questions). Frontend shows "Manual review required" instead of score.
- **Compliance auto-verify**: `POST /tprm/vendors/:id/compliance/auto-verify` bulk-upgrades `pending_review` docs with future expiry to `valid`/`expiring_soon`. PATCH compliance also auto-recalculates status from `expiresAt`.
- **Scan frequency options**: manual / daily / weekly / monthly — beat scheduler in beatScheduler.ts already has `daily: 86_400_000` interval.
