import { DgiiDirectoryService } from './dgii-directory.service';
import { DgiiEnvironment, DgiiSubmissionResponse } from '../types/dgii.types';
import { deepFindFirstString, parseXml } from '../utils/xml.utils';

function isTransientStatus(status: number) {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

function normalizeStatus(raw: unknown, httpStatus: number): DgiiSubmissionResponse['normalizedStatus'] {
  const statusText =
    deepFindFirstString(raw, ['Estado', 'estado', 'Status', 'status', 'Resultado', 'resultado'])?.toLowerCase() ?? '';

  if (statusText.includes('condicional')) return 'accepted_conditional';
  if (statusText.includes('acept')) return 'accepted';
  if (statusText.includes('rechaz')) return 'rejected';
  if (statusText.includes('pend') || statusText.includes('proces')) return 'pending';
  if (httpStatus >= 200 && httpStatus < 300) return 'pending';
  return 'error';
}

function extractCommonFields(raw: unknown) {
  return {
    trackId: deepFindFirstString(raw, ['TrackId', 'trackId', 'IdTrack', 'idTrack']),
    code: deepFindFirstString(raw, ['Codigo', 'codigo', 'Code', 'code']),
    message: deepFindFirstString(raw, ['Mensaje', 'mensaje', 'Descripcion', 'descripcion', 'Message', 'message']),
  };
}

async function parseResponse(response: Response) {
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) {
    return response.json();
  }

  const text = await response.text();
  if (!text.trim()) return {};

  try {
    return parseXml(text);
  } catch {
    return { rawText: text };
  }
}

export class DgiiSubmissionService {
  constructor(private readonly directory: DgiiDirectoryService) {}

  async submit(environment: DgiiEnvironment, signedXml: string): Promise<DgiiSubmissionResponse> {
    const config = this.directory.getEnvironmentConfig(environment);
    let attempt = 0;
    let lastError: unknown = null;

    while (attempt <= config.maxRetries) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), config.timeoutMs);

      try {
        const response = await fetch(config.submitUrl, {
          method: 'POST',
          headers: {
            'content-type': 'application/xml; charset=utf-8',
            accept: 'application/json, application/xml, text/xml;q=0.9, */*;q=0.8',
            'user-agent': config.userAgent,
            ...(config.bearerToken ? { authorization: `Bearer ${config.bearerToken}` } : {}),
          },
          body: signedXml,
          signal: controller.signal,
        });
        clearTimeout(timeout);

        const raw = await parseResponse(response);
        const common = extractCommonFields(raw);
        const normalizedStatus = normalizeStatus(raw, response.status);

        return {
          httpStatus: response.status,
          ok: response.ok,
          trackId: common.trackId,
          normalizedStatus,
          code: common.code,
          message: common.message,
          raw,
        };
      } catch (error) {
        clearTimeout(timeout);
        lastError = error;
        if (attempt >= config.maxRetries) break;
      }

      attempt += 1;
    }

    return {
      httpStatus: 0,
      ok: false,
      normalizedStatus: 'error',
      message: lastError instanceof Error ? lastError.message : 'Error enviando documento a DGII',
      raw: { error: lastError instanceof Error ? lastError.message : String(lastError) },
    };
  }

  isRetryableStatus(httpStatus: number) {
    return isTransientStatus(httpStatus);
  }
}