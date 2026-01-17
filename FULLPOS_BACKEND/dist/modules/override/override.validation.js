"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.auditQuerySchema = exports.verifySchema = exports.approveSchema = exports.requestSchema = void 0;
const zod_1 = require("zod");
exports.requestSchema = zod_1.z.object({
    companyId: zod_1.z.number().int().positive(),
    actionCode: zod_1.z.string().min(3),
    resourceType: zod_1.z.string().optional(),
    resourceId: zod_1.z.string().optional(),
    requestedById: zod_1.z.number().int().positive(),
    terminalId: zod_1.z.string().optional(),
    meta: zod_1.z.record(zod_1.z.any()).optional(),
});
exports.approveSchema = zod_1.z.object({
    companyId: zod_1.z.number().int().positive(),
    requestId: zod_1.z.number().int().positive(),
    approvedById: zod_1.z.number().int().positive(),
    expiresInSeconds: zod_1.z.number().int().min(30).max(600).optional(),
});
exports.verifySchema = zod_1.z.object({
    companyId: zod_1.z.number().int().positive(),
    token: zod_1.z.string().min(4),
    actionCode: zod_1.z.string().min(3),
    resourceType: zod_1.z.string().optional(),
    resourceId: zod_1.z.string().optional(),
    usedById: zod_1.z.number().int().positive(),
    terminalId: zod_1.z.string().optional(),
});
exports.auditQuerySchema = zod_1.z.object({
    companyId: zod_1.z.coerce.number().int().positive(),
    limit: zod_1.z.coerce.number().int().min(1).max(200).optional(),
});
