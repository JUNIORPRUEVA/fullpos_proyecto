"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.errorHandler = errorHandler;
exports.notFound = notFound;
const zod_1 = require("zod");
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function errorHandler(err, _req, res, _next) {
    if (err instanceof zod_1.ZodError) {
        return res.status(400).json({
            message: 'Validation error',
            issues: err.issues.map((issue) => ({ path: issue.path, message: issue.message })),
        });
    }
    if (err?.status) {
        return res.status(err.status).json({ message: err.message ?? 'Request error' });
    }
    console.error(err);
    return res.status(500).json({ message: 'Unexpected error' });
}
function notFound(_req, res) {
    res.status(404).json({ message: 'Not found' });
}
