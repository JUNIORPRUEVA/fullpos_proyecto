export type DgiiEnvironment = 'precertification' | 'production';

export interface DgiiEnvironmentConfig {
  environment: DgiiEnvironment;
  submitUrl: string;
  recepcionEcfUrl?: string;
  recepcionFcUrl?: string;
  resultUrlTemplate: string;
  authSeedUrl?: string;
  authValidateUrl?: string;
  timeoutMs: number;
  maxRetries: number;
  userAgent: string;
}

export interface DgiiSubmissionResponse {
  httpStatus: number;
  ok: boolean;
  trackId?: string;
  normalizedStatus: 'accepted' | 'accepted_conditional' | 'rejected' | 'pending' | 'error';
  code?: string;
  message?: string;
  dgiiEndpoint?: string;
  responseContentType?: string;
  responseHeaders?: Record<string, string>;
  rawText?: string;
  raw: unknown;
}

export interface DgiiTrackResultResponse {
  httpStatus: number;
  ok: boolean;
  trackId: string;
  normalizedStatus: 'accepted' | 'accepted_conditional' | 'rejected' | 'pending' | 'error';
  code?: string;
  message?: string;
  dgiiEndpoint?: string;
  responseContentType?: string;
  responseHeaders?: Record<string, string>;
  rawText?: string;
  raw: unknown;
}
