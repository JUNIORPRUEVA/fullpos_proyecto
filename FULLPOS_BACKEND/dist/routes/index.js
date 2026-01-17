"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_routes_1 = __importDefault(require("../modules/auth/auth.routes"));
const reports_routes_1 = __importDefault(require("../modules/reports/reports.routes"));
const downloads_routes_1 = __importDefault(require("../modules/downloads/downloads.routes"));
const override_routes_1 = __importDefault(require("../modules/override/override.routes"));
const router = (0, express_1.Router)();
router.use('/auth', auth_routes_1.default);
router.use('/reports', reports_routes_1.default);
router.use('/downloads', downloads_routes_1.default);
router.use('/override', override_routes_1.default);
exports.default = router;
