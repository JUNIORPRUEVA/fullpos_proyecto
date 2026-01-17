"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getOwnerAppConfig = getOwnerAppConfig;
const prisma_1 = require("../../config/prisma");
const env_1 = __importDefault(require("../../config/env"));
async function getOwnerAppConfig(companyId) {
    const company = companyId
        ? await prisma_1.prisma.company.findUnique({
            where: { id: companyId },
        })
        : null;
    return {
        androidUrl: company?.ownerAppAndroidUrl ?? env_1.default.OWNER_APP_ANDROID_URL ?? null,
        iosUrl: company?.ownerAppIosUrl ?? env_1.default.OWNER_APP_IOS_URL ?? null,
        version: company?.ownerAppVersion ?? env_1.default.OWNER_APP_VERSION ?? '1.0.0',
        companyId: company?.id ?? companyId ?? null,
    };
}
