"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.idParamSchema = exports.salesListQuerySchema = exports.rangeQuerySchema = void 0;
const zod_1 = require("zod");
const dateMessage = 'Formato de fecha v\u00e1lido YYYY-MM-DD';
const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
exports.rangeQuerySchema = zod_1.z.object({
    from: zod_1.z.string().regex(dateRegex, { message: dateMessage }),
    to: zod_1.z.string().regex(dateRegex, { message: dateMessage }),
});
exports.salesListQuerySchema = exports.rangeQuerySchema.extend({
    page: zod_1.z.coerce.number().int().min(1).optional(),
    pageSize: zod_1.z.coerce.number().int().min(1).max(100).optional(),
});
exports.idParamSchema = zod_1.z.object({
    id: zod_1.z.coerce.number().int().positive(),
});
