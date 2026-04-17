import env from '../../../config/env';
import { DgiiEnvironment, DgiiEnvironmentConfig } from '../types/dgii.types';

export class DgiiDirectoryService {
  getEnvironmentConfig(environment: DgiiEnvironment): DgiiEnvironmentConfig {
    const timeoutMs = env.DGII_REQUEST_TIMEOUT_MS;
    const maxRetries = env.DGII_REQUEST_MAX_RETRIES;
    const userAgent = env.DGII_HTTP_USER_AGENT?.trim() || 'FULLPOS-Backend/1.0';

    if (environment === 'production') {
      if (!env.DGII_PRODUCTION_SUBMIT_URL || !env.DGII_PRODUCTION_RESULT_URL_TEMPLATE) {
        throw {
          status: 500,
          message: 'Configuración DGII de producción incompleta',
          errorCode: 'DGII_PROD_CONFIG_MISSING',
        };
      }

      return {
        environment,
        submitUrl: env.DGII_PRODUCTION_SUBMIT_URL,
        resultUrlTemplate: env.DGII_PRODUCTION_RESULT_URL_TEMPLATE,
        bearerToken: env.DGII_PRODUCTION_BEARER_TOKEN,
        timeoutMs,
        maxRetries,
        userAgent,
      };
    }

    if (!env.DGII_PRECERT_SUBMIT_URL || !env.DGII_PRECERT_RESULT_URL_TEMPLATE) {
      throw {
        status: 500,
        message: 'Configuración DGII de pre-certificación incompleta',
        errorCode: 'DGII_PRECERT_CONFIG_MISSING',
      };
    };

    return {
      environment,
      submitUrl: env.DGII_PRECERT_SUBMIT_URL,
      resultUrlTemplate: env.DGII_PRECERT_RESULT_URL_TEMPLATE,
      bearerToken: env.DGII_PRECERT_BEARER_TOKEN,
      timeoutMs,
      maxRetries,
      userAgent,
    };
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