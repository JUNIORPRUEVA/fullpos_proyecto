# Integrations: Products (Read-only)

This backend exposes a **server-to-server integration** to read products scoped to the **integration token's company**.

## Security model (multi-tenant)

- FULLTECH (or any integrator) **must not** connect to the FULLPOS database directly.
- Integrators authenticate using an **Integration Token**.
- The token is **bound to one `companyId`** in FULLPOS.
- The token is stored **hashed** (`sha256(pepper + token)`), never in plaintext.
- The middleware injects `req.integration.companyId` and queries MUST filter by this value.
- Tenant/company isolation is enforced **server-side** (no `companyId` is accepted from the client).

## Endpoint

### GET `/api/integrations/products`

Auth:
- `Authorization: Bearer <integration_token>`
- Scope required: `products:read`

Query params:
- `limit` (optional, 1..500)
- `updated_since` (optional, RFC3339 datetime, e.g. `2026-02-27T00:00:00.000Z`)
- `cursor` (optional, opaque string returned by previous response)

Response:
```json
{
  "items": [
    {
      "id": 123,
      "sku": "ABC-001",
      "barcode": "ABC-001",
      "name": "Producto 1",
      "price": 199.99,
      "cost": 120.00,
      "stock": 5.000,
      "active": true,
      "updated_at": "2026-02-27T01:23:45.678Z"
    }
  ],
  "next_cursor": null
}
```

### GET `/api/integrations/health`

Una verificación simple de que el módulo de integraciones está montado y que la base de datos es alcanzable.

- No requiere token.
- No revela `companyId`, token, scopes ni información sensible.

Respuesta:

```json
{ "ok": true }
```

## Creating an integration token (server-side)

This prints the raw token **once** and stores only the hash.

```bash
npm run token:integration:create -- --companyId=133080206 --scopes=products:read --name=fulltech --expiresInDays=3650
```

Optional env:
- `INTEGRATION_TOKEN_PEPPER` (recommended in production)

Notes:
- The printed `token` value is the only secret you need. Store it server-side (e.g. FULLTECH backend env). Never store it in clients.
- Do not log/store the hash anywhere outside the DB.

## Smoke test (curl)

Replace `FULLPOS_BASE_URL` with your deployed base URL (no trailing `/`).

```bash
curl -sS \
  -H "Authorization: Bearer <TOKEN>" \
  "<FULLPOS_BASE_URL>/api/integrations/products?limit=5"
```

Expected success (example):

```json
{
  "items": [{ "id": 123, "name": "Producto 1" }],
  "next_cursor": null
}
```

Common failures:
- `401`: Missing/invalid/expired/revoked token.
- `403`: Token exists but missing scope `products:read`.
- `500`/`503`: DB not reachable or server error (check `DATABASE_URL`, migrations, logs).

## Quick tenant-isolation test

Requires a reachable `DATABASE_URL` and migrations applied.

```bash
npm run test:integration:products
```

This script creates two companies + products + tokens and asserts that Tenant A token cannot read Tenant B products.

## Verification checklist (FULLTECH rollout)

1) FULLPOS_BACKEND
- Run migrations (`prisma migrate deploy`).
- Create token for `companyId=133080206` with scope `products:read`.
- Verify: `GET /api/integrations/products?limit=5` returns your products.

2) FULLTECH backend
- Set env: `PRODUCTS_SOURCE=FULLPOS`.
- Set env: `FULLPOS_INTEGRATION_BASE_URL=<FULLPOS_BASE_URL>` (without `/api`).
- Set env: `FULLPOS_INTEGRATION_TOKEN=<TOKEN>`.
- Verify: `GET /products` returns the same products.
- Verify: product writes are blocked when read-only.

## Key files

- Model + migration:
  - prisma/schema.prisma (model `IntegrationToken`)
  - prisma/migrations/20260227020000_add_integration_tokens/migration.sql
- Auth + endpoint:
  - src/modules/integrations/integrations.auth.ts
  - src/modules/integrations/integrations.routes.ts
  - src/modules/integrations/integrations.products.service.ts
  - src/modules/integrations/integrations.validation.ts
- Test + tooling:
  - tools/create_integration_token.ts
  - tools/test_integration_products_tenant_isolation.ts
