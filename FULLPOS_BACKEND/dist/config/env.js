"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.corsOrigins = void 0;
const dotenv_1 = require("dotenv");
const zod_1 = require("zod");
(0, dotenv_1.config)();
const envSchema = zod_1.z.object({
    NODE_ENV: zod_1.z.enum(['development', 'production', 'test']).default('development'),
    PORT: zod_1.z.coerce.number().int().min(1).max(65535).default(4000),
    DATABASE_URL: zod_1.z.string().url(),
    JWT_ACCESS_SECRET: zod_1.z.string().min(16),
    JWT_REFRESH_SECRET: zod_1.z.string().min(16),
    JWT_ACCESS_EXPIRES_IN: zod_1.z.string().default('15m'),
    JWT_REFRESH_EXPIRES_IN: zod_1.z.string().default('7d'),
    CORS_ORIGINS: zod_1.z.string().optional(),
    OWNER_APP_ANDROID_URL: zod_1.z.string().optional(),
    OWNER_APP_IOS_URL: zod_1.z.string().optional(),
    OWNER_APP_VERSION: zod_1.z.string().optional()
});
const env = envSchema.parse(process.env);
exports.corsOrigins = env.CORS_ORIGINS?.split(',').map((origin) => origin.trim()).filter(Boolean) ?? ['*'];
exports.default = env;
