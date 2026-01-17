"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const validate_1 = require("../../middlewares/validate");
const downloads_service_1 = require("./downloads.service");
const downloads_validation_1 = require("./downloads.validation");
const router = (0, express_1.Router)();
router.get('/owner-app', (0, validate_1.validate)(downloads_validation_1.downloadQuerySchema, 'query'), async (req, res, next) => {
    try {
        const { companyId } = req.query;
        const config = await (0, downloads_service_1.getOwnerAppConfig)(companyId ? Number(companyId) : undefined);
        res.json(config);
    }
    catch (err) {
        next(err);
    }
});
exports.default = router;
