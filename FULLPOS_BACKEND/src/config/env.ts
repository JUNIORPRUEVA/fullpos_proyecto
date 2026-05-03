import { config } from 'dotenv';
import { z } from 'zod';

config();

function optionalTrimmedString(value: unknown) {
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function parseBooleanEnv(value: unknown) {
  if (typeof value === 'boolean') return value;
  if (typeof value !== 'string') return value;
  const normalized = value.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off', ''].includes(normalized)) return false;
  return value;
}

const optionalUrl = z.preprocess(optionalTrimmedString, z.string().url().optional());
const DGII_CERTIFICATION_AUTH_SEED_URL = 'https://ecf.dgii.gov.do/certecf/autenticacion/api/autenticacion/semilla';
const DGII_CERTIFICATION_AUTH_VALIDATE_URL = 'https://ecf.dgii.gov.do/certecf/autenticacion/api/autenticacion/validarsemilla';
const DGII_CERTIFICATION_RECEPCION_ECF_URL = 'https://ecf.dgii.gov.do/certecf/recepcion/api/facturaselectronicas';
const DGII_CERTIFICATION_RECEPCION_FC_URL = 'https://fc.dgii.gov.do/certecf/recepcionfc/api/recepcion/ecf';
const DGII_CERTIFICATION_RESULT_URL_TEMPLATE =
  'https://ecf.dgii.gov.do/certecf/consultaresultado/api/consultas/estado?trackid={trackId}';
const urlWithBlankDefault = (defaultValue: string) =>
  z.preprocess((value) => optionalTrimmedString(value) ?? defaultValue, z.string().url());
const stringWithBlankDefault = (defaultValue: string) =>
  z.preprocess((value) => optionalTrimmedString(value) ?? defaultValue, z.string());

export function normalizeDgiiEnvironmentAlias(value: unknown) {
  if (typeof value !== 'string') return value;
  const normalized = value.trim().toLowerCase();
  if (
    normalized === 'precertification' ||
    normalized === 'certification' ||
    normalized === 'certificacion' ||
    normalized === 'test' ||
    normalized === 'prueba' ||
    normalized === 'pruebas' ||
    normalized === 'testecf' ||
    normalized === 'precert'
  ) {
    return 'precertification';
  }
  if (normalized === 'production' || normalized === 'produccion') {
    return 'production';
  }
  return normalized;
}

const dgiiDefaultEnvironmentSchema = z.preprocess(normalizeDgiiEnvironmentAlias, z.enum(['precertification', 'production']));

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  DATABASE_URL: z.string().url(),
  JWT_ACCESS_SECRET: z.string().min(16),
  JWT_REFRESH_SECRET: z.string().min(16),
  JWT_ACCESS_EXPIRES_IN: z.string().default('15m'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),
  CORS_ORIGINS: z.string().optional(),
  OVERRIDE_API_KEY: z.string().optional(),
  ALLOW_PUBLIC_CLOUD: z.preprocess(parseBooleanEnv, z.boolean().optional()),
  REDIS_URL: z.preprocess(optionalTrimmedString, z.string().url().optional()),
  // Optional pepper for hashing integration tokens (recommended in prod)
  INTEGRATION_TOKEN_PEPPER: z.string().optional(),
  // Clave maestra para derivar el secret del token virtual (TOTP) por terminal.
  // Si no está configurada, el token virtual queda deshabilitado.
  VIRTUAL_TOKEN_MASTER_KEY: z.string().min(16).optional(),
  // Uploads
  UPLOADS_DIR: z.string().optional(),
  PUBLIC_BASE_URL: optionalUrl,
  MAX_PRODUCT_IMAGES_PER_COMPANY: z.coerce.number().int().min(1).optional(),
  MAX_UPLOAD_IMAGE_MB: z.coerce.number().int().min(1).optional(),
  MAX_IMAGE_WIDTH: z.coerce.number().int().min(200).optional(),
  MAX_IMAGE_HEIGHT: z.coerce.number().int().min(200).optional(),
  MAX_BACKUP_MB: z.coerce.number().int().min(10).optional(),
  BACKUPS_DIR: z.string().optional(),
  BACKUPS_TMP_DIR: z.string().optional(),
  SUPPORT_LOGS_DIR: z.string().optional(),
  MAX_SUPPORT_LOG_MB: z.coerce.number().int().min(1).optional(),
  OWNER_APP_ANDROID_URL: z.string().optional(),
  OWNER_APP_IOS_URL: z.string().optional(),
  OWNER_APP_VERSION: z.string().optional(),
  DANGER_ACTION_PIN: z.string().min(4).optional(),
  FE_MASTER_ENCRYPTION_KEY: z.string().min(32).optional(),
  FE_SEED_TTL_SECONDS: z.coerce.number().int().min(30).max(3600).default(300),
  FE_PUBLIC_TOKEN_TTL_SECONDS: z.coerce.number().int().min(30).max(86400).default(300),
  DGII_REQUEST_TIMEOUT_MS: z.coerce.number().int().min(1000).max(120000).default(15000),
  DGII_REQUEST_MAX_RETRIES: z.coerce.number().int().min(0).max(10).default(2),
  DGII_HTTP_USER_AGENT: z.string().optional(),
  DGII_ALLOW_PRODUCTION: z.preprocess(parseBooleanEnv, z.boolean().default(false)),
  DGII_DEFAULT_ENVIRONMENT: dgiiDefaultEnvironmentSchema.default('precertification'),
  DGII_TOKEN_CACHE_SKEW_SECONDS: z.coerce.number().int().min(0).max(3600).default(60),
  DGII_PRECERT_SUBMIT_URL: urlWithBlankDefault(DGII_CERTIFICATION_RECEPCION_ECF_URL),
  DGII_PRECERT_RECEPCION_ECF_URL: urlWithBlankDefault(DGII_CERTIFICATION_RECEPCION_ECF_URL),
  DGII_PRECERT_RECEPCION_FC_URL: urlWithBlankDefault(DGII_CERTIFICATION_RECEPCION_FC_URL),
  DGII_PRECERT_RESULT_URL_TEMPLATE: stringWithBlankDefault(DGII_CERTIFICATION_RESULT_URL_TEMPLATE),
  DGII_PRECERT_AUTH_SEED_URL: urlWithBlankDefault(DGII_CERTIFICATION_AUTH_SEED_URL),
  DGII_PRECERT_AUTH_VALIDATE_URL: urlWithBlankDefault(DGII_CERTIFICATION_AUTH_VALIDATE_URL),
  DGII_PRECERT_BEARER_TOKEN: z.string().optional(),
  DGII_PRODUCTION_SUBMIT_URL: z.preprocess(optionalTrimmedString, z.string().optional()),
  DGII_PRODUCTION_RECEPCION_ECF_URL: z.preprocess(optionalTrimmedString, z.string().optional()),
  DGII_PRODUCTION_RECEPCION_FC_URL: z.preprocess(optionalTrimmedString, z.string().optional()),
  DGII_PRODUCTION_RESULT_URL_TEMPLATE: z.string().optional(),
  DGII_PRODUCTION_AUTH_SEED_URL: z.preprocess(optionalTrimmedString, z.string().optional()),
  DGII_PRODUCTION_AUTH_VALIDATE_URL: z.preprocess(optionalTrimmedString, z.string().optional()),
  DGII_PRODUCTION_BEARER_TOKEN: z.string().optional()
});

const env = envSchema.parse(process.env);

if (env.NODE_ENV === 'production') {
  if (env.ALLOW_PUBLIC_CLOUD === true) {
    console.warn(
      '[SECURITY WARNING] ALLOW_PUBLIC_CLOUD=true in production. ' +
      'Cloud sync endpoints are publicly accessible without an API key. ' +
      'Set ALLOW_PUBLIC_CLOUD=false and configure OVERRIDE_API_KEY to harden this deployment.',
    );
  }

  const overrideApiKey = env.OVERRIDE_API_KEY?.trim();
  if (!overrideApiKey) {
    console.warn(
      '[SECURITY WARNING] OVERRIDE_API_KEY is not set in production. ' +
      'Cloud sync endpoints have no API key protection. ' +
      'Set OVERRIDE_API_KEY to a strong secret to secure this deployment.',
    );
  }
}

export const corsOrigins =
  env.CORS_ORIGINS?.split(',').map((origin) => origin.trim()).filter(Boolean) ?? ['*'];

export default env;
