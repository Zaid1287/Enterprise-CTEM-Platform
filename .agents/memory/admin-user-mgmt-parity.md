---
name: Admin User Management Parity
description: Fixes needed to make admin User Management match super_admin — tenant ID field, create restrictions, tenantId reassignment.
---

## Rules

1. **Edit User form Tenant ID**: show for `isAdminOrSA`, not just `isSuperAdmin`. Use a select dropdown (not raw number input) populated from GET /tenants.
2. **handleSave tenantId**: send for `isAdminOrSA` (not `isSuperAdmin`). Guard: only send if changed.
3. **handleSave role**: only send if `editState.role !== editUser.role`. Super_admin user's role is rendered as a locked badge — never sent in PATCH.
4. **No creating super_admin**: remove "super_admin" from ROLE_OPTIONS.super_admin (frontend) and ROLE_HIERARCHY.super_admin (backend).
5. **Backend PATCH tenantId**: extend from `super_admin` only → `super_admin || admin`.
6. **Backend POST create user with tenantId**: platform admin (isPlatform=true) skips the parentTenantId child-tenant check — allowed any tenant (same as super_admin). Non-platform admin still restricted to child tenants.

**Why:** Tenants 2/3/4 were created by super_admin → parentTenantId=null. Admin's parentTenantId check would always fail for these tenants. Platform admin (tenant 1, isPlatform=true) has SA-level scope.

**How to apply:** Whenever extending super_admin capabilities to admin in users.ts or UsersPage.tsx, check both the tenantId-assignment flow AND the parentTenantId restriction — they are separate code paths.
