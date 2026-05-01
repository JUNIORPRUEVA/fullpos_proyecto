import env from '../../../config/env';
import { DgiiEnvironment, DgiiEnvironmentConfig } from '../types/dgii.types';

function detectAuthEndpointFamily(url?: string) {
  const value = (url ?? '').toLowerCase();
  if (!value) return 'missing';
  if (value.includes('/autenticacion/api/autenticacion/')) return 'autenticacion-api-autenticacion';
  if (value.includes('/emisorreceptor/fe/autenticacion/api/')) return 'emisorreceptor-fe-autenticacion-api';
  return 'other';
}

const CERTIFICATION_ENDPOINTS = {
  authSeedUrl: 'https://ecf.dgii.gov.do/certecf/autenticacion/api/autenticacion/semilla',
  authValidateUrl: 'https://ecf.dgii.gov.do/certecf/autenticacion/api/autenticacion/validarsemilla',
  recepcionEcfUrl: 'https://ecf.dgii.gov.do/certecf/recepcion/api/facturaselectronicas',
  recepcionFcUrl: 'https://fc.dgii.gov.do/certecf/recepcionfc/api/recepcion/ecf',
  resultUrlTemplate: 'https://ecf.dgii.gov.do/certecf/consultaresultado/api/consultas/estado?trackid={trackId}',
};

function normalizeCerteCfUrl(value: string) {
  return value.trim()
    .replace(/\/testecf\//ig, '/certecf/')
    .replace(/\/test\//ig, '/certecf/');
}

function normalizeCertificationEndpoint(
  value: string | undefined,
  kind: keyof typeof CERTIFICATION_ENDPOINTS,
) {
  const input = value?.trim();
  if (!input) return CERTIFICATION_ENDPOINTS[kind];

  const normalized = normalizeCerteCfUrl(input);
  const lower = normalized.toLowerCase().replace(/\/+$/, '');

  if (kind === 'authSeedUrl') {
    if (lower.endsWith('/certecf/autenticacion')) return CERTIFICATION_ENDPOINTS.authSeedUrl;
    if (lower.includes('/autenticacion/api/autenticacion/semilla')) return normalized;
    return CERTIFICATION_ENDPOINTS.authSeedUrl;
  }
  if (kind === 'authValidateUrl') {
    if (lower.endsWith('/certecf/autenticacion')) return CERTIFICATION_ENDPOINTS.authValidateUrl;
    if (lower.includes('/autenticacion/api/autenticacion/validarsemilla')) return normalized;
    if (lower.includes('/autenticacion/api/semilla/validacioncertificado')) return normalized;
    return CERTIFICATION_ENDPOINTS.authValidateUrl;
  }
  if (kind === 'recepcionEcfUrl') {
    if (lower.endsWith('/certecf/recepcion')) return CERTIFICATION_ENDPOINTS.recepcionEcfUrl;
    if (lower.includes('/recepcion/api/facturaselectronicas')) return normalized;
    return CERTIFICATION_ENDPOINTS.recepcionEcfUrl;
  }
  if (kind === 'recepcionFcUrl') {
    if (lower.endsWith('/certecf/recepcionfc')) return CERTIFICATION_ENDPOINTS.recepcionFcUrl;
    if (lower.includes('/recepcionfc/api/recepcion/ecf')) return normalized;
    return CERTIFICATION_ENDPOINTS.recepcionFcUrl;
  }
  if (kind === 'resultUrlTemplate') {
    if (lower.endsWith('/certecf/consultaresultado')) return CERTIFICATION_ENDPOINTS.resultUrlTemplate;
    if (lower.includes('/consultaresultado/api/consultas/estado')) return normalized;
    return CERTIFICATION_ENDPOINTS.resultUrlTemplate;
  }

  return normalized;
}

export class DgiiDirectoryService {
  getEnvironmentConfig(environment: DgiiEnvironment): DgiiEnvironmentConfig {
    const timeoutMs = env.DGII_REQUEST_TIMEOUT_MS;
    const maxRetries = env.DGII_REQUEST_MAX_RETRIES;
    const userAgent = env.DGII_HTTP_USER_AGENT?.trim() || 'FULLPOS-Backend/1.0';

    if (environment === 'production') {
      if (!env.DGII_ALLOW_PRODUCTION) {
        throw {
          status: 409,
          message: 'El ambiente DGII de producción está bloqueado en este backend',
          errorCode: 'DGII_PRODUCTION_DISABLED',
        };
      }

      const productionSubmitUrl = env.DGII_PRODUCTION_RECEPCION_ECF_URL || env.DGII_PRODUCTION_SUBMIT_URL;
      if (!productionSubmitUrl || !env.DGII_PRODUCTION_RESULT_URL_TEMPLATE) {
        throw {
          status: 500,
          message: 'Configuración DGII de producción incompleta',
          errorCode: 'DGII_PROD_CONFIG_MISSING',
        };
      }

      return {
        environment,
        submitUrl: productionSubmitUrl,
        recepcionEcfUrl: env.DGII_PRODUCTION_RECEPCION_ECF_URL || env.DGII_PRODUCTION_SUBMIT_URL,
        recepcionFcUrl: env.DGII_PRODUCTION_RECEPCION_FC_URL,
        resultUrlTemplate: env.DGII_PRODUCTION_RESULT_URL_TEMPLATE,
        authSeedUrl: env.DGII_PRODUCTION_AUTH_SEED_URL,
        authValidateUrl: env.DGII_PRODUCTION_AUTH_VALIDATE_URL,
        timeoutMs,
        maxRetries,
        userAgent,
      };
    }

    const precertSubmitUrl = normalizeCertificationEndpoint(
      env.DGII_PRECERT_RECEPCION_ECF_URL || env.DGII_PRECERT_SUBMIT_URL,
      'recepcionEcfUrl',
    );
    if (!precertSubmitUrl || !env.DGII_PRECERT_RESULT_URL_TEMPLATE) {
      throw {
        status: 500,
        message: 'Configuración DGII de pre-certificación incompleta',
        errorCode: 'DGII_PRECERT_CONFIG_MISSING',
      };
    };

    const config: DgiiEnvironmentConfig = {
      environment,
      submitUrl: precertSubmitUrl,
      recepcionEcfUrl: precertSubmitUrl,
      recepcionFcUrl: normalizeCertificationEndpoint(env.DGII_PRECERT_RECEPCION_FC_URL, 'recepcionFcUrl'),
      resultUrlTemplate: normalizeCertificationEndpoint(env.DGII_PRECERT_RESULT_URL_TEMPLATE, 'resultUrlTemplate'),
      authSeedUrl: normalizeCertificationEndpoint(env.DGII_PRECERT_AUTH_SEED_URL, 'authSeedUrl'),
      authValidateUrl: normalizeCertificationEndpoint(env.DGII_PRECERT_AUTH_VALIDATE_URL, 'authValidateUrl'),
      timeoutMs,
      maxRetries,
      userAgent,
    };

    console.info('[electronic-invoicing.dgii.directory] auth.endpoints', {
      environment,
      authSeedUrl: config.authSeedUrl ?? null,
      authValidateUrl: config.authValidateUrl ?? null,
      authSeedFamily: detectAuthEndpointFamily(config.authSeedUrl),
      authValidateFamily: detectAuthEndpointFamily(config.authValidateUrl),
    });

    return config;
  }

  buildTrackResultUrl(template: string, trackId: string) {
    if (template.includes('{trackId}')) {
      return template.split('{trackId}').join(encodeURIComponent(trackId));
    }
    if (template.includes(':trackId')) {
      return template.split(':trackId').join(encodeURIComponent(trackId));
    }

    const url = new URL(template);
    url.searchParams.set('trackId', trackId);
    return url.toString();
  }
}
