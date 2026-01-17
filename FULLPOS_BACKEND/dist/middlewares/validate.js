"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validate = validate;
function validate(schema, part = 'body') {
    return (req, _res, next) => {
        const parsed = schema.safeParse(req[part]);
        if (!parsed.success) {
            const err = parsed.error;
            return next(err);
        }
        // Replace the parsed payload to ensure types downstream
        req[part] = parsed.data;
        next();
    };
}
