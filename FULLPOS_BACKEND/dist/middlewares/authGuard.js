"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authGuard = authGuard;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const env_1 = __importDefault(require("../config/env"));
function authGuard(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Token requerido' });
    }
    const token = authHeader.substring(7);
    try {
        const payload = jsonwebtoken_1.default.verify(token, env_1.default.JWT_ACCESS_SECRET);
        req.user = {
            id: payload.id,
            companyId: payload.companyId,
            username: payload.username,
            role: payload.role,
            email: payload.email,
        };
        return next();
    }
    catch (err) {
        return res.status(401).json({ message: 'Token inv\u00e1lido o expirado' });
    }
}
