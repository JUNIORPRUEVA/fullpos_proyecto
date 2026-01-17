"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createOverrideRequest = createOverrideRequest;
exports.approveOverride = approveOverride;
exports.verifyOverride = verifyOverride;
exports.getAudit = getAudit;
const crypto_1 = __importDefault(require("crypto"));
const prisma_1 = require("../../config/prisma");
const DEFAULT_TTL_SECONDS = 180;
const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function hashToken(token) {
    return crypto_1.default.createHash('sha256').update(token).digest('hex');
}
function randomToken(length) {
    return Array.from({ length }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join('');
}
async function createOverrideRequest(body) {
    const created = await prisma_1.prisma.overrideRequest.create({
        data: {
            companyId: body.companyId,
            actionCode: body.actionCode,
            resourceType: body.resourceType,
            resourceId: body.resourceId,
            requestedById: body.requestedById,
            terminalId: body.terminalId,
            meta: body.meta,
        },
    });
    await prisma_1.prisma.auditLog.create({
        data: {
            companyId: body.companyId,
            actionCode: body.actionCode,
            resourceType: body.resourceType,
            resourceId: body.resourceId,
            requestedById: body.requestedById,
            approvedById: null,
            method: 'remote',
            result: 'requested',
            terminalId: body.terminalId,
            meta: body.meta,
        },
    });
    return { requestId: created.id, status: created.status };
}
async function approveOverride(body) {
    const ttl = body.expiresInSeconds ?? DEFAULT_TTL_SECONDS;
    const token = randomToken(10);
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + ttl * 1000);
    try {
        const [request, tokenRecord] = await prisma_1.prisma.$transaction(async (trx) => {
            const request = await trx.overrideRequest.update({
                where: { id: body.requestId },
                data: {
                    status: 'approved',
                    approvedById: body.approvedById,
                    tokenHash,
                    expiresAt,
                    resolvedAt: new Date(),
                },
            });
            const tokenRecord = await trx.overrideToken.create({
                data: {
                    companyId: body.companyId,
                    actionCode: request.actionCode,
                    resourceType: request.resourceType,
                    resourceId: request.resourceId,
                    tokenHash,
                    method: 'remote',
                    nonce: randomToken(8),
                    requestedById: request.requestedById,
                    approvedById: body.approvedById,
                    expiresAt,
                    terminalId: request.terminalId,
                    requestId: request.id,
                },
            });
            await trx.auditLog.create({
                data: {
                    companyId: body.companyId,
                    actionCode: request.actionCode,
                    resourceType: request.resourceType,
                    resourceId: request.resourceId,
                    requestedById: request.requestedById,
                    approvedById: body.approvedById,
                    method: 'remote',
                    result: 'approved',
                    terminalId: request.terminalId,
                },
            });
            return [request, tokenRecord];
        });
        return {
            requestId: request.id,
            token,
            expiresAt,
            tokenId: tokenRecord.id,
        };
    }
    catch (e) {
        throw { status: 400, message: e.message ?? 'No se pudo aprobar la solicitud' };
    }
}
async function verifyOverride(body) {
    const tokenHash = hashToken(body.token);
    try {
        const result = await prisma_1.prisma.$transaction(async (trx) => {
            const token = await trx.overrideToken.findFirst({
                where: {
                    companyId: body.companyId,
                    actionCode: body.actionCode,
                    tokenHash,
                },
            });
            if (!token)
                throw new Error('Token inv\u00e1lido');
            if (token.usedAt)
                throw new Error('Token ya usado');
            if (token.expiresAt.getTime() < Date.now())
                throw new Error('Token vencido');
            if (token.resourceType && body.resourceType && token.resourceType !== body.resourceType)
                throw new Error('Token no coincide con el recurso');
            if (token.resourceId && body.resourceId && token.resourceId !== body.resourceId)
                throw new Error('Token no coincide con el recurso');
            await trx.overrideToken.update({
                where: { id: token.id },
                data: { usedAt: new Date(), usedById: body.usedById, result: 'approved' },
            });
            await trx.auditLog.create({
                data: {
                    companyId: body.companyId,
                    actionCode: token.actionCode,
                    resourceType: token.resourceType,
                    resourceId: token.resourceId,
                    requestedById: token.requestedById,
                    approvedById: body.usedById,
                    method: token.method,
                    result: 'approved',
                    terminalId: body.terminalId,
                },
            });
            return token;
        });
        return { ok: true, tokenId: result.id };
    }
    catch (e) {
        await prisma_1.prisma.auditLog.create({
            data: {
                companyId: body.companyId,
                actionCode: body.actionCode,
                resourceType: body.resourceType,
                resourceId: body.resourceId,
                requestedById: body.usedById,
                approvedById: null,
                method: 'remote',
                result: 'rejected',
                terminalId: body.terminalId,
                meta: { error: e.message },
            },
        });
        throw { status: 400, message: e.message ?? 'No autorizado' };
    }
}
async function getAudit(companyId, limit = 100) {
    const audits = await prisma_1.prisma.auditLog.findMany({
        where: { companyId },
        orderBy: { createdAt: 'desc' },
        take: limit,
    });
    return audits;
}
