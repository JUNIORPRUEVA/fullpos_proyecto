import { DgiiDirectoryService } from './dgii-directory.service';
import { DgiiEnvironment, DgiiTrackResultResponse } from '../types/dgii.types';
import { deepFindFirstString, parseXml } from '../utils/xml.utils';

async function parseResultResponse(response: Response) {
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

function normalizeStatus(raw: unknown, httpStatus: number): DgiiTrackResultResponse['normalizedStatus'] {
  const statusText =
    deepFindFirstString(raw, ['Estado', 'estado', 'Status', 'status', 'Resultado', 'resultado'])?.toLowerCase() ?? '';

  if (statusText.includes('condicional')) return 'accepted_conditional';
  if (statusText.includes('acept')) return 'accepted';
  if (statusText.includes('rechaz')) return 'rejected';
  if (statusText.includes('pend') || statusText.includes('proces')) return 'pending';
  if (httpStatus >= 200 && httpStatus < 300) return 'pending';
  return 'error';
}

export class DgiiResultService {
  constructor(private readonly directory: DgiiDirectoryService) {}

  async query(environment: DgiiEnvironment, trackId: string): Promise<DgiiTrackResultResponse> {
    const config = this.directory.getEnvironmentConfig(environment);
    const url = this.directory.buildTrackResultUrl(config.resultUrlTemplate, trackId);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.timeoutMs);

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          accept: 'application/json, application/xml, text/xml;q=0.9, */*;q=0.8',
          'user-agent': config.userAgent,
          ...(config.bearerToken ? { authorization: `Bearer ${config.bearerToken}` } : {}),
        },
        signal: controller.signal,
      });
      clearTimeout(timeout);

      const raw = await parseResultResponse(response);
      return {
        httpStatus: response.status,
        ok: response.ok,
        trackId,
        normalizedStatus: normalizeStatus(raw, response.status),
        code: deepFindFirstString(raw, ['Codigo', 'codigo', 'Code', 'code']),
        message: deepFindFirstString(raw, ['Mensaje', 'mensaje', 'Descripcion', 'descripcion', 'Message', 'message']),
        raw,
      };
    } catch (error) {
      clearTimeout(timeout);
      return {
        httpStatus: 0,
        ok: false,
        trackId,
        normalizedStatus: 'error',
        message: error instanceof Error ? error.message : 'Error consultando TrackId DGII',
        raw: { error: error instanceof Error ? error.message : String(error) },
      };
    }
  }
}