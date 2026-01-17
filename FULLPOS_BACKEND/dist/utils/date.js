"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseRange = parseRange;
exports.ensureRangeWithinDays = ensureRangeWithinDays;
const date_fns_1 = require("date-fns");
function parseRange(from, to) {
    const fromDate = (0, date_fns_1.startOfDay)((0, date_fns_1.parseISO)(from));
    const toDate = (0, date_fns_1.endOfDay)((0, date_fns_1.parseISO)(to));
    if (Number.isNaN(fromDate.getTime()) || Number.isNaN(toDate.getTime())) {
        throw new Error('Rango de fechas inv\u00e1lido');
    }
    if ((0, date_fns_1.isAfter)(fromDate, toDate)) {
        throw new Error('from must be before or equal to to');
    }
    return { fromDate, toDate };
}
function ensureRangeWithinDays(fromDate, toDate, maxDays) {
    const limitDate = new Date(fromDate);
    limitDate.setDate(limitDate.getDate() + maxDays);
    if ((0, date_fns_1.isBefore)(limitDate, toDate)) {
        throw new Error(`Range cannot exceed ${maxDays} days`);
    }
}
