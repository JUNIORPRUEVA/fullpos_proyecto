"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const authGuard_1 = require("../../middlewares/authGuard");
const validate_1 = require("../../middlewares/validate");
const reports_service_1 = require("./reports.service");
const reports_validation_1 = require("./reports.validation");
const router = (0, express_1.Router)();
router.get('/sales/summary', authGuard_1.authGuard, (0, validate_1.validate)(reports_validation_1.rangeQuerySchema, 'query'), async (req, res, next) => {
    try {
        const { from, to } = req.query;
        const result = await (0, reports_service_1.getSalesSummary)(req.user.companyId, from, to);
        res.json(result);
    }
    catch (err) {
        next(err);
    }
});
router.get('/sales/by-day', authGuard_1.authGuard, (0, validate_1.validate)(reports_validation_1.rangeQuerySchema, 'query'), async (req, res, next) => {
    try {
        const { from, to } = req.query;
        const result = await (0, reports_service_1.getSalesByDay)(req.user.companyId, from, to);
        res.json(result);
    }
    catch (err) {
        next(err);
    }
});
router.get('/sales/list', authGuard_1.authGuard, (0, validate_1.validate)(reports_validation_1.salesListQuerySchema, 'query'), async (req, res, next) => {
    try {
        const { from, to, page, pageSize } = req.query;
        const result = await (0, reports_service_1.getSalesList)(req.user.companyId, from, to, page ? Number(page) : 1, pageSize ? Number(pageSize) : 20);
        res.json(result);
    }
    catch (err) {
        next(err);
    }
});
router.get('/cash/closings', authGuard_1.authGuard, (0, validate_1.validate)(reports_validation_1.rangeQuerySchema, 'query'), async (req, res, next) => {
    try {
        const { from, to } = req.query;
        const result = await (0, reports_service_1.getCashClosings)(req.user.companyId, from, to);
        res.json(result);
    }
    catch (err) {
        next(err);
    }
});
router.get('/cash/closing/:id', authGuard_1.authGuard, (0, validate_1.validate)(reports_validation_1.idParamSchema, 'params'), async (req, res, next) => {
    try {
        const { id } = req.params;
        const result = await (0, reports_service_1.getCashClosingDetail)(req.user.companyId, Number(id));
        res.json(result);
    }
    catch (err) {
        next(err);
    }
});
exports.default = router;
