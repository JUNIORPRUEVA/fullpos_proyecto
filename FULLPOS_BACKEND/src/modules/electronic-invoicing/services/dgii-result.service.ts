import { DgiiDirectoryService } from './dgii-directory.service';
import { DgiiAuthService } from './dgii-auth.service';
import { DgiiEnvironment, DgiiTrackResultResponse } from '../types/dgii.types';
import { deepFindFirstString, parseXml } from '../utils/xml.utils';

function isAuthFailure(httpStatus: number, code?: string, message?: string) {
  if (httpStatus === 401 || httpStatus === 403) return true;
  const fingerprint = `${code ?? ''} ${message ?? ''}`.toLowerCase();
  return fingerprint.includes('token') || fingerprint.includes('bearer') || fingerprint.includes('unauthor') || fingerprint.includes('autoriz');
}

async function parseResultResponse(response: Response) {
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) {
    const parsed = await response.json();
    return {
      raw: parsed,
      rawText: typeof parsed === 'string' ? parsed : JSON.stringify(parsed),
      contentType,
    };
  }

  const text = await response.text();
  if (!text.trim()) return { raw: {}, rawText: '', contentType };
  try {
    return { raw: parseXml(text), rawText: text, contentType };
  } catch {
    return { raw: { rawText: text }, rawText: text, contentType };
  }
}

function normalizeStatus(raw: unknown, httpStatus: number): DgiiTrackResultResponse['normalizedStatus'] {
  const statusText =
    deepFindFirstString(raw, ['Estado', 'estado', 'Status', 'status', 'Resultado', 'resultado'])?.toLowerCase() ?? '';
  const messageText =
    deepFindFirstString(raw, ['Mensaje', 'mensaje', 'Descripcion', 'descripcion', 'Message', 'message'])?.toLowerCase() ?? '';

  if (statusText.includes('error') || messageText.includes('error')) return 'error';

  if (statusText.includes('condicional')) return 'accepted_conditional';
  if (statusText.includes('acept')) return 'accepted';
  if (statusText.includes('rechaz')) return 'rejected';
  if (statusText.includes('pend') || statusText.includes('proces')) return 'pending';
  if (httpStatus >= 200 && httpStatus < 300) return 'pending';
  return 'error';
}

function sanitizeResponseHeaders(response: Response) {
  const relevant = ['content-type', 'date', 'server', 'x-request-id', 'x-correlation-id'];
  const out: Record<string, string> = {};
  for (const name of relevant) {
    const value = response.headers.get(name);
    if (value) out[name] = value;
  }
  return out;
}

export class DgiiResultService {
  constructor(
    private readonly directory: DgiiDirectoryService,
    private readonly authService: DgiiAuthService,
  ) {}

  async query(companyId: number, environment: DgiiEnvironment, trackId: string, requestId?: string): Promise<DgiiTrackResultResponse> {
    const config = this.directory.getEnvironmentConfig(environment);
    const url = this.directory.buildTrackResultUrl(config.resultUrlTemplate, trackId);
    for (let forceRefresh = false; ; forceRefresh = true) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), config.timeoutMs);

      try {
        const bearerToken = await this.authService.getCompanyBearerToken(companyId, environment, requestId, {
          forceRefresh,
        });
        const response = await fetch(url, {
          method: 'GET',
          headers: {
            accept: 'application/json, application/xml, text/xml;q=0.9, */*;q=0.8',
            'user-agent': config.userAgent,
            authorization: `Bearer ${bearerToken}`,
          },
          signal: controller.signal,
        });
        clearTimeout(timeout);

        const parsed = await parseResultResponse(response);
        const raw = parsed.raw;
        const code = deepFindFirstString(raw, ['Codigo', 'codigo', 'Code', 'code']);
        const message = deepFindFirstString(raw, ['Mensaje', 'mensaje', 'Descripcion', 'descripcion', 'Message', 'message']);
        const normalizedStatus = normalizeStatus(raw, response.status);
        const responseHeaders = sanitizeResponseHeaders(response);

        console.info('[electronic-invoicing.dgii.result] dgii_result_received', {
          requestId,
          companyId,
          environment,
          trackId,
          endpoint: url,
          httpStatus: response.status,
          contentType: parsed.contentType,
          headers: responseHeaders,
          normalizedStatus,
          code: code ?? null,
          message: message ?? null,
          rawText: parsed.rawText,
          rawParsed: raw,
        });

        if (!forceRefresh && isAuthFailure(response.status, code, message)) {
          await this.authService.invalidateCompanyBearerToken(companyId, environment, message ?? code);
          continue;
        }

        return {
          httpStatus: response.status,
          ok: response.ok,
          trackId,
          normalizedStatus,
          code,
          message,
          dgiiEndpoint: url,
          responseContentType: parsed.contentType,
          responseHeaders,
          rawText: parsed.rawText,
          raw,
        };
      } catch (error) {
        clearTimeout(timeout);
        return {
          httpStatus: 0,
          ok: false,
          trackId,
          normalizedStatus: 'error',
          code: 'TRACK_QUERY_ERROR',
          message: error instanceof Error ? error.message : 'Error consultando TrackId DGII',
          dgiiEndpoint: url,
          raw: { error: error instanceof Error ? error.message : String(error) },
        };
      }
    }
  }
}