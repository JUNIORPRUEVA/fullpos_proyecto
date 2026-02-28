import assert from 'assert';
import crypto from 'crypto';
import request from 'supertest';
import env from '../src/config/env';
import app from '../src/app';
import { prisma } from '../src/config/prisma';

function hashToken(rawToken: string) {
  const pepper = env.INTEGRATION_TOKEN_PEPPER?.trim() ?? '';
  return crypto.createHash('sha256').update(`${pepper}${rawToken}`).digest('hex');
}

async function main() {
  await prisma.$connect();

  const unique = crypto.randomBytes(6).toString('hex');
  const companyA = await prisma.company.create({ data: { name: `test_company_a_${unique}` } });
  const companyB = await prisma.company.create({ data: { name: `test_company_b_${unique}` } });

  const productA1 = await prisma.product.create({
    data: {
      companyId: companyA.id,
      code: `A-${unique}-1`,
      name: `Product A1 ${unique}`,
      description: null,
      price: 10,
      cost: 5,
      stock: 3,
      imageUrl: null,
      isDemo: false,
    },
  });
  const productB1 = await prisma.product.create({
    data: {
      companyId: companyB.id,
      code: `B-${unique}-1`,
      name: `Product B1 ${unique}`,
      description: null,
      price: 20,
      cost: 8,
      stock: 7,
      imageUrl: null,
      isDemo: false,
    },
  });

  const rawTokenA = crypto.randomBytes(32).toString('hex');
  const rawTokenB = crypto.randomBytes(32).toString('hex');
  await prisma.integrationToken.create({
    data: {
      companyId: companyA.id,
      name: 'tenant-a',
      tokenHash: hashToken(rawTokenA),
      scopes: ['products:read'],
    },
  });
  await prisma.integrationToken.create({
    data: {
      companyId: companyB.id,
      name: 'tenant-b',
      tokenHash: hashToken(rawTokenB),
      scopes: ['products:read'],
    },
  });

  const resA = await request(app)
    .get('/api/integrations/products?limit=100')
    .set('Authorization', `Bearer ${rawTokenA}`)
    .expect(200);

  assert(Array.isArray(resA.body.items), 'items should be an array');
  const idsA = new Set(resA.body.items.map((p: any) => p.id));
  assert(idsA.has(productA1.id), 'Company A token should see A product');
  assert(!idsA.has(productB1.id), 'Company A token must not see B product');

  const resB = await request(app)
    .get('/api/integrations/products?limit=100')
    .set('Authorization', `Bearer ${rawTokenB}`)
    .expect(200);

  const idsB = new Set(resB.body.items.map((p: any) => p.id));
  assert(idsB.has(productB1.id), 'Company B token should see B product');
  assert(!idsB.has(productA1.id), 'Company B token must not see A product');

  // eslint-disable-next-line no-console
  console.log('OK: integration tenant isolation test passed');
}

main()
  .catch((err) => {
    // eslint-disable-next-line no-console
    console.error('FAILED: integration tenant isolation test failed');
    // eslint-disable-next-line no-console
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect().catch(() => undefined);
  });
