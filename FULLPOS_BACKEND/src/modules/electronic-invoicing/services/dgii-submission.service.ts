import { DgiiDirectoryService } from './dgii-directory.service';
import { DgiiAuthService } from './dgii-auth.service';
import { DgiiEnvironment, DgiiSubmissionResponse } from '../types/dgii.types';
import { deepFindFirstString, parseXml } from '../utils/xml.utils';

type UnknownErrorShape = {
  errorCode?: string;
  message?: string;
  status?: number;
  details?: unknown;
  stack?: string;
};

function isTransientStatus(status: number) {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

function shouldRetryNormalizedError(error: { status?: number; code: string }, phase: 'token' | 'submit') {
  if (typeof error.status === 'number') {
    return isTransientStatus(error.status);
  }

  // When token bootstrap fails without explicit status, avoid futile retries on known functional/auth errors.
  if (phase === 'token') {
    if (error.code === 'DGII_SEED_VALIDATE_BAD_REQUEST') return false;
    if (error.code === 'DGII_SEED_REQUEST_FAILED') return false;
    if (error.code === 'DGII_TOKEN_MISSING') return false;
  }

  return true;
}

function normalizeStatus(raw: unknown, httpStatus: number): DgiiSubmissionResponse['normalizedStatus'] {
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

function extractCommonFields(raw: unknown) {
  const trackId = deepFindFirstString(raw, ['TrackId', 'trackId', 'TrackID', 'IdTrack', 'idTrack', 'NroTrackId']);
  return {
    trackId,
    code: deepFindFirstString(raw, ['Codigo', 'codigo', 'Code', 'code']),
    message: deepFindFirstString(raw, ['Mensaje', 'mensaje', 'Descripcion', 'descripcion', 'Message', 'message']),
  };
}

function isAuthFailure(httpStatus: number, code?: string, message?: string) {
  if (httpStatus === 401 || httpStatus === 403) return true;
  const fingerprint = `${code ?? ''} ${message ?? ''}`.toLowerCase();
  return fingerprint.includes('token') || fingerprint.includes('bearer') || fingerprint.includes('unauthor') || fingerprint.includes('autoriz');
}

async function parseResponse(response: Response) {
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

function extractTrackIdFromRawText(rawText?: string) {
  const text = (rawText ?? '').trim();
  if (!text) return undefined;

  const xmlMatch = text.match(/<(?:\w+:)?(?:TrackId|TrackID|IdTrack|idTrack|NroTrackId)>([^<]+)</i);
  if (xmlMatch?.[1]) return xmlMatch[1].trim();

  const jsonMatch = text.match(/"(?:TrackId|trackId|TrackID|IdTrack|idTrack|NroTrackId)"\s*:\s*"([^"]+)"/i);
  if (jsonMatch?.[1]) return jsonMatch[1].trim();

  return undefined;
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

function summarizeStack(stack?: string) {
  if (!stack) return undefined;
  return stack.split('\n').slice(0, 5).join('\n');
}

function summarizeRawBody(rawText?: string) {
  if (!rawText) return undefined;
  const trimmed = rawText.trim();
  if (!trimmed) return undefined;
  return trimmed.length > 1200 ? `${trimmed.slice(0, 1200)}...` : trimmed;
}

function normalizeUnknownError(
  error: unknown,
  phase: 'token' | 'submit',
  hasManualToken: boolean,
): { code: string; message: string; status?: number; details?: unknown; stack?: string } {
  if (error instanceof Error) {
    return {
      code: phase === 'token' && !hasManualToken ? 'DGII_TOKEN_GENERATION_FAILED' : 'SEND_ERROR',
      message: error.message,
      stack: summarizeStack(error.stack),
    };
  }

  const shaped = (error ?? {}) as UnknownErrorShape;
  const candidateCode = typeof shaped.errorCode === 'string' ? shaped.errorCode : undefined;
  const candidateMessage = typeof shaped.message === 'string' ? shaped.message : undefined;

  return {
    code: candidateCode ?? (phase === 'token' && !hasManualToken ? 'DGII_TOKEN_GENERATION_FAILED' : 'SEND_ERROR'),
    message: candidateMessage ?? 'Error enviando documento a DGII',
    status: typeof shaped.status === 'number' ? shaped.status : undefined,
    details: shaped.details,
    stack: summarizeStack(shaped.stack),
  };
}

export class DgiiSubmissionService {
  constructor(
    private readonly directory: DgiiDirectoryService,
    private readonly authService: DgiiAuthService,
  ) {}

  async submit(
    companyId: number,
    environment: DgiiEnvironment,
    signedXml: string,
    requestId?: string,
    manualToken?: string,
    context?: { invoiceId?: number; ecf?: string },
  ): Promise<DgiiSubmissionResponse> {
    const config = this.directory.getEnvironmentConfig(environment);
    let attempt = 0;
    let lastError: unknown = null;
    let forceRefresh = false;
    let lastPhase: 'token' | 'submit' = 'submit';

    while (attempt <= config.maxRetries) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), config.timeoutMs);

      try {
        lastPhase = 'token';
        const tokenResult = await this.authService.getCompanyBearerTokenWithMeta(companyId, environment, requestId, {
          forceRefresh,
          manualToken,
        });
        const bearerToken = tokenResult.token;

        console.info('[electronic-invoicing.dgii.submit] request', {
          requestId,
          companyId,
          invoiceId: context?.invoiceId ?? null,
          ecf: context?.ecf ?? null,
          environment,
          endpoint: config.submitUrl,
          hasToken: !!bearerToken,
          tokenSource: tokenResult.source,
          xmlSize: signedXml.length,
          signedXmlPresent: signedXml.length > 0,
          attempt,
        });

        lastPhase = 'submit';
        const response = await fetch(config.submitUrl, {
          method: 'POST',
          headers: {
            'content-type': 'application/xml; charset=utf-8',
            accept: 'application/json, application/xml, text/xml;q=0.9, */*;q=0.8',
            'user-agent': config.userAgent,
            authorization: `Bearer ${bearerToken}`,
          },
          body: signedXml,
          signal: controller.signal,
        });
        clearTimeout(timeout);

        const parsed = await parseResponse(response);
        const raw = parsed.raw;
        const common = extractCommonFields(raw);
        const trackId = common.trackId ?? extractTrackIdFromRawText(parsed.rawText);
        const normalizedStatus = normalizeStatus(raw, response.status);
        const responseHeaders = sanitizeResponseHeaders(response);

        console.info('[electronic-invoicing.dgii.submit] response', {
          requestId,
          companyId,
          invoiceId: context?.invoiceId ?? null,
          ecf: context?.ecf ?? null,
          environment,
          endpoint: config.submitUrl,
          dgiiHttpStatus: response.status,
          contentType: parsed.contentType,
          headers: responseHeaders,
          trackId: trackId ?? null,
          dgiiStatus: normalizedStatus,
          rejectionCode: common.code ?? null,
          rejectionMessage: common.message ?? null,
          rawBodySummary: summarizeRawBody(parsed.rawText),
          rawParsed: raw,
        });

        if (!manualToken && !forceRefresh && isAuthFailure(response.status, common.code, common.message)) {
          await this.authService.invalidateCompanyBearerToken(companyId, environment, common.message ?? common.code);
          forceRefresh = true;
          attempt += 1;
          continue;
        }

        return {
          httpStatus: response.status,
          ok: response.ok,
          trackId,
          normalizedStatus,
          code: common.code,
          message: common.message,
          dgiiEndpoint: config.submitUrl,
          responseContentType: parsed.contentType,
          responseHeaders,
          rawText: parsed.rawText,
          raw,
        };
      } catch (error) {
        clearTimeout(timeout);
        lastError = error;
        const normalized = normalizeUnknownError(error, lastPhase, !!manualToken?.trim());

        console.error('[electronic-invoicing.dgii.submit] error', {
          requestId,
          companyId,
          invoiceId: context?.invoiceId ?? null,
          ecf: context?.ecf ?? null,
          environment,
          endpoint: config.submitUrl,
          phase: lastPhase,
          errorCode: normalized.code,
          errorMessage: normalized.message,
          stack: normalized.stack,
          responseStatus: normalized.status ?? null,
          responseBody: normalized.details ?? null,
          attempt,
        });

        const retryable = shouldRetryNormalizedError({ status: normalized.status, code: normalized.code }, lastPhase);
        if (!retryable) {
          break;
        }

        if (attempt >= config.maxRetries) break;
      }

      attempt += 1;
    }

    const normalized = normalizeUnknownError(lastError, lastPhase, !!manualToken?.trim());
    return {
      httpStatus: 0,
      ok: false,
      normalizedStatus: 'error',
      code: normalized.code,
      message: normalized.message,
      dgiiEndpoint: config.submitUrl,
      raw: {
        phase: lastPhase,
        error: normalized.message,
        errorCode: normalized.code,
        responseStatus: normalized.status ?? null,
        responseBody: normalized.details ?? null,
      },
    };
  }

  isRetryableStatus(httpStatus: number) {
    return isTransientStatus(httpStatus);
  }
}