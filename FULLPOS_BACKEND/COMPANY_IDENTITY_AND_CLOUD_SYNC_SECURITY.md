# FULLPOS Cloud Identity and Security Hardening

## Unique Company Identity Model

Primary identity key:
- `companyTenantKey`

Construction inputs (client side):
- `normalizedRnc` when available, otherwise `companyCloudId`
- `businessId`
- `terminalId` (also sent as `deviceId`)

Current Flutter source of truth:
- `CloudCompanyIdentityService.resolve(settings)`

Current backend resolver:
- `resolveCompanyIdentity(...)`

Resolution order:
1. Exact `companyTenantKey`
2. `companyCloudId` with anti-conflict validation
3. `normalizedRnc` only when non-ambiguous

Conflict policy:
- Identity mismatches are rejected with 4xx conflict errors.
- Ambiguous RNC-only matching is rejected.
- Safe self-heal is allowed only for reparable `normalizedRnc` corruption, then persisted.

## Security Hardening Applied

### 1) Upload identity hardening
- Product image upload now requires `companyTenantKey`.
- Upload identity is resolved through `resolveCompanyIdentity`.
- Auxiliary identity fields are accepted (`companyRnc`, `companyCloudId`, `businessId`, `deviceId`, `terminalId`) but tenant key is mandatory.
- Conflicts between tenant key and other locators are rejected by resolver rules.
- Old image file deletion is allowed only when the URL belongs to a product in the resolved company.
- Image delete endpoint now also validates tenant identity and company ownership before deleting files.

### 2) Production startup hardening
When `NODE_ENV=production`:
- `ALLOW_PUBLIC_CLOUD` must not be `true`
- `OVERRIDE_API_KEY` must be present and non-empty
- Backend throws at startup when invalid

### 3) Rate limiting
Applied to cloud entrypoints used by POS sync/upload:
- `*/sync/by-rnc`
- `/products/sync/operations`
- `/auth/sync-users`
- `/companies/config/by-rnc`
- `/uploads/product-image`
- Realtime socket handshake path (in gateway)

Identity key selection for rate-limit buckets:
1. `companyTenantKey`
2. `companyCloudId`
3. IP fallback

Policy defaults:
- sync: 240 requests / minute
- uploads: 40 requests / minute
- realtime handshakes: 120 / minute

### 4) Logging hardening
- Sync logs redact identity values (`companyTenantKey`, `companyCloudId`, `companyRnc`).
- Product sync operation routes no longer print full raw/parsed payloads in production.
- Full payload logging is only allowed when explicitly enabled outside production via `DEBUG_SYNC_PAYLOAD=true`.

## Operational Notes
- This hardening preserves offline-first queue behavior.
- Existing sync contracts remain valid; identity fields are now stricter for uploads.
- Existing image URLs are not rewritten; only ownership checks were added before deletion.
