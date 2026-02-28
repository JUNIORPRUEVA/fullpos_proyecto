import crypto from 'crypto';
import env from '../src/config/env';
import { prisma } from '../src/config/prisma';

function parseArg(name: string) {
  const arg = process.argv.find((a) => a.startsWith(`--${name}=`));
  if (!arg) return null;
  return arg.substring(name.length + 3).trim();
}

function hashToken(rawToken: string) {
  const pepper = env.INTEGRATION_TOKEN_PEPPER?.trim() ?? '';
  return crypto.createHash('sha256').update(`${pepper}${rawToken}`).digest('hex');
}

async function main() {
  const companyIdRaw = parseArg('companyId');
  const scopesRaw = parseArg('scopes') ?? 'products:read';
  const name = parseArg('name');
  const expiresInDaysRaw = parseArg('expiresInDays');

  if (!companyIdRaw) {
    throw new Error('Missing --companyId=NUMBER');
  }

  const companyId = Number(companyIdRaw);
  if (!Number.isFinite(companyId) || companyId <= 0) {
    throw new Error('Invalid --companyId');
  }

  const scopes = scopesRaw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  if (scopes.length === 0) {
    throw new Error('Invalid --scopes (empty)');
  }

  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(rawToken);

  const expiresAt = (() => {
    if (!expiresInDaysRaw) return null;
    const days = Number(expiresInDaysRaw);
    if (!Number.isFinite(days) || days <= 0) throw new Error('Invalid --expiresInDays');
    return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  })();

  await prisma.$connect();

  const token = await prisma.integrationToken.create({
    data: {
      companyId,
      name: name?.trim() || null,
      tokenHash,
      scopes,
      expiresAt,
    },
  });

  // Print raw token once. Store this value server-side (e.g. FULLTECH backend env), never in clients.
  // eslint-disable-next-line no-console
  console.log('Integration token created:');
  // eslint-disable-next-line no-console
  console.log(JSON.stringify({
    id: token.id,
    companyId: token.companyId,
    scopes: token.scopes,
    expiresAt: token.expiresAt,
    token: rawToken,
  }, null, 2));
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
