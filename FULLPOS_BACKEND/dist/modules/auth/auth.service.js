"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.login = login;
exports.refresh = refresh;
exports.getProfile = getProfile;
exports.ensureUserPassword = ensureUserPassword;
const crypto_1 = __importDefault(require("crypto"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const prisma_1 = require("../../config/prisma");
const env_1 = __importDefault(require("../../config/env"));
const password_1 = require("../../utils/password");
function parseDurationToMs(duration) {
    const fallback = 15 * 60 * 1000;
    const match = duration.trim().match(/^(\d+)\s*([smhd])?$/i);
    if (!match)
        return fallback;
    const value = Number(match[1]);
    const unit = match[2]?.toLowerCase() ?? 's';
    const ms = unit === 'd'
        ? value * 24 * 60 * 60 * 1000
        : unit === 'h'
            ? value * 60 * 60 * 1000
            : unit === 'm'
                ? value * 60 * 1000
                : value * 1000;
    return ms > 0 ? ms : fallback;
}
function buildJwtPayload(user) {
    return {
        id: user.id,
        companyId: user.companyId,
        username: user.username,
        role: user.role,
        email: user.email ?? undefined,
    };
}
async function createRefreshToken(userId) {
    const rawToken = crypto_1.default.randomBytes(32).toString('hex');
    const tokenHash = crypto_1.default.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = new Date(Date.now() + parseDurationToMs(env_1.default.JWT_REFRESH_EXPIRES_IN));
    await prisma_1.prisma.refreshToken.create({
        data: {
            tokenHash,
            userId,
            expiresAt,
        },
    });
    return { token: rawToken, expiresAt };
}
async function deleteRefreshToken(tokenHash) {
    await prisma_1.prisma.refreshToken.deleteMany({
        where: { tokenHash },
    });
}
async function generateTokenPair(user) {
    const accessToken = jsonwebtoken_1.default.sign(user, env_1.default.JWT_ACCESS_SECRET, { expiresIn: env_1.default.JWT_ACCESS_EXPIRES_IN });
    const refresh = await createRefreshToken(user.id);
    const expiresInSeconds = Math.floor(parseDurationToMs(env_1.default.JWT_ACCESS_EXPIRES_IN) / 1000);
    return {
        accessToken,
        refreshToken: refresh.token,
        expiresIn: expiresInSeconds,
    };
}
async function login(identifier, password) {
    const user = await prisma_1.prisma.user.findFirst({
        where: {
            isActive: true,
            OR: [{ username: identifier }, { email: identifier }],
        },
        include: { company: true },
    });
    if (!user || !user.company.isActive) {
        throw { status: 401, message: 'Credenciales inv\u00e1lidas' };
    }
    const passwordMatches = await (0, password_1.verifyPassword)(password, user.password);
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
async function refresh(refreshToken) {
    const tokenHash = crypto_1.default.createHash('sha256').update(refreshToken).digest('hex');
    const stored = await prisma_1.prisma.refreshToken.findUnique({
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
async function getProfile(userId) {
    const user = await prisma_1.prisma.user.findFirst({
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
async function ensureUserPassword(userId, password) {
    const hashed = await (0, password_1.hashPassword)(password);
    await prisma_1.prisma.user.update({
        where: { id: userId },
        data: { password: hashed },
    });
}
