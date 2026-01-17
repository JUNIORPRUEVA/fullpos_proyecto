import crypto from 'crypto';
import jwt, { JwtPayload, Secret, SignOptions } from 'jsonwebtoken';
import { prisma } from '../../config/prisma';
import env from '../../config/env';
import { verifyPassword, hashPassword } from '../../utils/password';
import { JwtUser, TokenPair } from './auth.types';

function parseDurationToMs(duration: string): number {
  const fallback = 15 * 60 * 1000;
  const match = duration.trim().match(/^(\d+)\s*([smhd])?$/i);
  if (!match) return fallback;

  const value = Number(match[1]);
  const unit = match[2]?.toLowerCase() ?? 's';

  const ms =
    unit === 'd'
      ? value * 24 * 60 * 60 * 1000
      : unit === 'h'
        ? value * 60 * 60 * 1000
        : unit === 'm'
          ? value * 60 * 1000
          : value * 1000;

  return ms > 0 ? ms : fallback;
}

function buildJwtPayload(user: {
  id: number;
  companyId: number;
  username: string;
  role: string;
  email: string | null;
}): JwtUser {
  return {
    id: user.id,
    companyId: user.companyId,
    username: user.username,
    role: user.role,
    email: user.email ?? undefined,
  };
}

async function createRefreshToken(userId: number) {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const expiresAt = new Date(Date.now() + parseDurationToMs(env.JWT_REFRESH_EXPIRES_IN));

  await prisma.refreshToken.create({
    data: {
      tokenHash,
      userId,
      expiresAt,
    },
  });

  return { token: rawToken, expiresAt };
}

async function deleteRefreshToken(tokenHash: string) {
  await prisma.refreshToken.deleteMany({
    where: { tokenHash },
  });
}

async function generateTokenPair(user: JwtUser): Promise<TokenPair> {
  const accessToken = jwt.sign(
    user as JwtPayload,
    env.JWT_ACCESS_SECRET as Secret,
    { expiresIn: env.JWT_ACCESS_EXPIRES_IN } as SignOptions,
  );

  const refresh = await createRefreshToken(user.id);
  const expiresInSeconds = Math.floor(parseDurationToMs(env.JWT_ACCESS_EXPIRES_IN) / 1000);

  return {
    accessToken,
    refreshToken: refresh.token,
    expiresIn: expiresInSeconds,
  };
}

export async function login(identifier: string, password: string) {
  const user = await prisma.user.findFirst({
    where: {
      isActive: true,
      OR: [{ username: identifier }, { email: identifier }],
    },
    include: { company: true },
  });

  if (!user || !user.company.isActive) {
    throw { status: 401, message: 'Credenciales inv\u00e1lidas' };
  }

  const passwordMatches = await verifyPassword(password, user.password);
  if (!passwordMatches) {
    throw { status: 401, message: 'Credenciales inv\u00e1lidas' };
  }

  const payload = buildJwtPayload(user);
  const tokens = await generateTokenPair(payload);

  return {
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      companyId: user.companyId,
      displayName: user.displayName,
    },
    company: {
      id: user.company.id,
      name: user.company.name,
      rnc: user.company.rnc,
      androidUrl: user.company.ownerAppAndroidUrl,
      iosUrl: user.company.ownerAppIosUrl,
      version: user.company.ownerAppVersion,
    },
    tokens,
  };
}

export async function refresh(refreshToken: string) {
  const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
  const stored = await prisma.refreshToken.findUnique({
    where: { tokenHash },
    include: {
      user: { include: { company: true } },
    },
  });

  if (!stored || stored.expiresAt.getTime() < Date.now() || stored.user.isActive === false) {
    throw { status: 401, message: 'Token de refresh inv\u00e1lido' };
  }

  // Rotate token
  await deleteRefreshToken(tokenHash);

  const payload = buildJwtPayload(stored.user);
  const tokens = await generateTokenPair(payload);

  return {
    user: {
      id: stored.user.id,
      username: stored.user.username,
      email: stored.user.email,
      role: stored.user.role,
      companyId: stored.user.companyId,
      displayName: stored.user.displayName,
    },
    company: {
      id: stored.user.company.id,
      name: stored.user.company.name,
      rnc: stored.user.company.rnc,
      androidUrl: stored.user.company.ownerAppAndroidUrl,
      iosUrl: stored.user.company.ownerAppIosUrl,
      version: stored.user.company.ownerAppVersion,
    },
    tokens,
  };
}

export async function getProfile(userId: number) {
  const user = await prisma.user.findFirst({
    where: { id: userId, isActive: true },
    include: { company: true },
  });

  if (!user || !user.company.isActive) {
    throw { status: 401, message: 'Usuario no encontrado o inactivo' };
  }

  return {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    displayName: user.displayName,
    company: {
      id: user.company.id,
      name: user.company.name,
      rnc: user.company.rnc,
      androidUrl: user.company.ownerAppAndroidUrl,
      iosUrl: user.company.ownerAppIosUrl,
      version: user.company.ownerAppVersion,
    },
  };
}

// Utilidad para el seeding
export async function ensureUserPassword(userId: number, password: string) {
  const hashed = await hashPassword(password);
  await prisma.user.update({
    where: { id: userId },
    data: { password: hashed },
  });
}
