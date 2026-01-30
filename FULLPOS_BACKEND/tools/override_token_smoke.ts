import crypto from 'crypto';
import { PrismaClient } from '@prisma/client';
import dotenv from 'dotenv';
import { verifyOverride } from '../src/modules/override/override.service';

const prisma = new PrismaClient();

dotenv.config();

function arg(name: string) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return null;
  return process.argv[idx + 1] ?? null;
}

function hashToken(token: string) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function randomToken(len = 10) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return Array.from({ length: len }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join(
    '',
  );
}

const VIRTUAL_PERIOD_SECONDS = 30;
const VIRTUAL_DIGITS = 6;

function virtualSecretFor(companyId: number, terminalId: string) {
  const masterKey = (process.env.VIRTUAL_TOKEN_MASTER_KEY ?? '').trim();
  if (!masterKey) return null;

  const h = crypto.createHmac('sha256', masterKey).update(`${companyId}|${terminalId}`).digest();
  return h.subarray(0, 20);
}

function totpAt(secret: Buffer, timeMs: number) {
  const counter = Math.floor(timeMs / 1000 / VIRTUAL_PERIOD_SECONDS);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));

  const hmac = crypto.createHmac('sha1', secret).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = (hmac.readUInt32BE(offset) & 0x7fffffff) >>> 0;
  const mod = 10 ** VIRTUAL_DIGITS;
  const code = String(binary % mod).padStart(VIRTUAL_DIGITS, '0');

  return { code, counter };
}

async function callVerify(payload: any) {
  try {
    const ok = await verifyOverride(payload);
    return { ok: true, value: ok };
  } catch (e: any) {
    return {
      ok: false,
      error: {
        status: e?.status ?? 500,
        message: e?.message ?? String(e),
        errorCode: e?.errorCode ?? 'UNKNOWN',
        details: e?.details ?? null,
      },
    };
  }
}

async function main() {
  // Nota: este smoke test llama verifyOverride() directo (sin HTTP).
  let cloudCompanyId = arg('--cloudCompanyId');
  let username = arg('--username');
  let email = arg('--email');
  let terminalDeviceId = arg('--terminalDeviceId');
  const actionCode = arg('--actionCode') ?? 'TEST_OVERRIDE';

  // Auto-pick sane defaults if not provided.
  if (!cloudCompanyId) {
    const c = await prisma.company.findFirst({
      where: { cloudCompanyId: { not: null } },
      select: { cloudCompanyId: true },
      orderBy: { id: 'asc' },
    });
    cloudCompanyId = c?.cloudCompanyId ?? null;
  }
  if (!cloudCompanyId) throw new Error('Missing --cloudCompanyId and no Company.cloudCompanyId found');

  const company = await prisma.company.findFirst({
    where: { cloudCompanyId },
    select: { id: true, cloudCompanyId: true },
  });
  if (!company) throw new Error(`Company not found cloudCompanyId=${cloudCompanyId}`);

  if (!username && !email) {
    const u = await prisma.user.findFirst({
      where: { companyId: company.id, isActive: true },
      select: { username: true, email: true },
      orderBy: { id: 'asc' },
    });
    username = u?.username ?? null;
    email = u?.email ?? null;
  }
  if (!username && !email) throw new Error('Missing --username/--email and no active user found for company');

  if (!terminalDeviceId) {
    const t = await prisma.terminal.findFirst({
      where: { companyId: company.id, isActive: true },
      select: { deviceId: true },
      orderBy: { id: 'asc' },
    });
    terminalDeviceId = t?.deviceId ?? null;
  }

  const user = await prisma.user.findFirst({
    where: {
      companyId: company.id,
      isActive: true,
      OR: [email ? { email: email.toLowerCase() } : undefined, username ? { username } : undefined].filter(
        Boolean,
      ) as any,
    },
    select: { id: true, username: true, email: true },
  });
  if (!user) throw new Error('User not found for company');

  if (terminalDeviceId) {
    const terminal = await prisma.terminal.findFirst({
      where: { companyId: company.id, deviceId: terminalDeviceId, isActive: true },
      select: { id: true },
    });
    if (!terminal) throw new Error(`Terminal not found deviceId=${terminalDeviceId}`);
  }

  const token = randomToken(10);
  const tokenHash = hashToken(token);

  const created = await prisma.overrideToken.create({
    data: {
      companyId: company.id,
      actionCode,
      tokenHash,
      method: 'remote',
      nonce: randomToken(8),
      requestedById: user.id,
      approvedById: user.id,
      expiresAt: new Date(Date.now() + 2 * 60 * 1000),
      terminalId: terminalDeviceId ?? null,
    },
    select: { id: true },
  });

  const payload = {
    cloudCompanyId,
    token,
    actionCode,
    cloudUserId: user.id,
    cloudTerminalId: terminalDeviceId ?? undefined,
    meta: { smoke: true },
  };

  console.log('--- Concurrent verify (expected: 1 ok, 1 used) ---');
  const [a, b] = await Promise.all([callVerify(payload), callVerify(payload)]);
  console.log('A:', a);
  console.log('B:', b);

  console.log('--- Invalid token ---');
  const invalid = await callVerify({ ...payload, token: '000000', cloudUserId: user.id });
  console.log('Invalid:', invalid);

  console.log('--- Expired token ---');
  const expiredToken = randomToken(10);
  await prisma.overrideToken.create({
    data: {
      companyId: company.id,
      actionCode,
      tokenHash: hashToken(expiredToken),
      method: 'remote',
      nonce: randomToken(8),
      requestedById: user.id,
      approvedById: user.id,
      expiresAt: new Date(Date.now() - 60 * 1000),
      terminalId: terminalDeviceId ?? null,
    },
  });
  const expired = await callVerify({ ...payload, token: expiredToken, cloudUserId: user.id });
  console.log('Expired:', expired);

  console.log('--- Non-existent user (precheck, should not write) ---');
  const badUser = await callVerify({ ...payload, cloudUserId: 999999999 });
  console.log('BadUser:', badUser);

  console.log('--- Virtual token (TOTP) ---');
  if (!terminalDeviceId) {
    console.log('Virtual: skipped (no terminalDeviceId found)');
  } else {
    const secret = virtualSecretFor(company.id, terminalDeviceId);
    if (!secret) {
      console.log('Virtual: skipped (VIRTUAL_TOKEN_MASTER_KEY not set)');
    } else {
      // Use current window token.
      const { code } = totpAt(secret, Date.now());

      // For virtual path, remote token must not exist; use a different actionCode.
      const virtualPayload = {
        cloudCompanyId,
        token: code,
        actionCode: 'TEST_OVERRIDE_VIRTUAL',
        cloudUserId: user.id,
        cloudTerminalId: terminalDeviceId,
        meta: { smoke: true, virtual: true },
      };

      const [v1, v2] = await Promise.all([callVerify(virtualPayload), callVerify(virtualPayload)]);
      console.log('Virtual A:', v1);
      console.log('Virtual B:', v2);
    }
  }

  // Cleanup best-effort
  await prisma.overrideToken.deleteMany({ where: { id: created.id } });

  console.log('Done.');
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
