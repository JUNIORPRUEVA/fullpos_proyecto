"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.downloadQuerySchema = void 0;
const zod_1 = require("zod");
exports.downloadQuerySchema = zod_1.z.object({
    companyId: zod_1.z.coerce.number().int().positive().optional(),
});
