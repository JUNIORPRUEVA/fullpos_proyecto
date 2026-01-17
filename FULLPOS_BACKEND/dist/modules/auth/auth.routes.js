"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const authGuard_1 = require("../../middlewares/authGuard");
const validate_1 = require("../../middlewares/validate");
const auth_validation_1 = require("./auth.validation");
const auth_service_1 = require("./auth.service");
const router = (0, express_1.Router)();
router.post('/login', (0, validate_1.validate)(auth_validation_1.loginSchema), async (req, res, next) => {
    try {
        const { identifier, password } = req.body;
        const result = await (0, auth_service_1.login)(identifier, password);
        res.json(result);
    }
    catch (err) {
        next(err);
    }
});
router.post('/refresh', (0, validate_1.validate)(auth_validation_1.refreshSchema), async (req, res, next) => {
    try {
        const { refreshToken } = req.body;
        const result = await (0, auth_service_1.refresh)(refreshToken);
        res.json(result);
    }
    catch (err) {
        next(err);
    }
});
router.get('/me', authGuard_1.authGuard, async (req, res, next) => {
    try {
        const profile = await (0, auth_service_1.getProfile)(req.user.id);
        res.json(profile);
    }
    catch (err) {
        next(err);
    }
});
exports.default = router;
