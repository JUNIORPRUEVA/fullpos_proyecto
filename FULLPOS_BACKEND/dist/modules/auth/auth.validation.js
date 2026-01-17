"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.refreshSchema = exports.loginSchema = void 0;
const zod_1 = require("zod");
exports.loginSchema = zod_1.z.object({
    identifier: zod_1.z.string().min(3, 'Usuario o correo requerido'),
    password: zod_1.z.string().min(4, 'Contrase\u00f1a requerida'),
});
exports.refreshSchema = zod_1.z.object({
    refreshToken: zod_1.z.string().min(10, 'Token requerido'),
});
