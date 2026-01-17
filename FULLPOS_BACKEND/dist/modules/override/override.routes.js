"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const validate_1 = require("../../middlewares/validate");
const override_validation_1 = require("./override.validation");
const override_service_1 = require("./override.service");
const router = (0, express_1.Router)();
router.post('/request', (0, validate_1.validate)(override_validation_1.requestSchema), async (req, res, next) => {
    try {
        const result = await (0, override_service_1.createOverrideRequest)(req.body);
        res.json(result);
    }
    catch (err) {
        next(err);
    }
});
router.post('/approve', (0, validate_1.validate)(override_validation_1.approveSchema), async (req, res, next) => {
    try {
        const result = await (0, override_service_1.approveOverride)(req.body);
        res.json(result);
    }
    catch (err) {
        next(err);
    }
});
router.post('/verify', (0, validate_1.validate)(override_validation_1.verifySchema), async (req, res, next) => {
    try {
        const result = await (0, override_service_1.verifyOverride)(req.body);
        res.json(result);
    }
    catch (err) {
        next(err);
    }
});
router.get('/audit', (0, validate_1.validate)(override_validation_1.auditQuerySchema, 'query'), async (req, res, next) => {
    try {
        const { companyId, limit } = req.query;
        const audits = await (0, override_service_1.getAudit)(Number(companyId), limit ? Number(limit) : 100);
        res.json(audits);
    }
    catch (err) {
        next(err);
    }
});
exports.default = router;
