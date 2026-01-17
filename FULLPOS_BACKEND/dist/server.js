"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const app_1 = __importDefault(require("./app"));
const env_1 = __importDefault(require("./config/env"));
const prisma_1 = require("./config/prisma");
const port = env_1.default.PORT;
async function bootstrap() {
    await prisma_1.prisma.$connect();
    app_1.default.listen(port, () => {
        console.log(`FULLPOS backend running on port ${port}`);
    });
}
bootstrap().catch((err) => {
    console.error('Failed to start server', err);
    process.exit(1);
});
