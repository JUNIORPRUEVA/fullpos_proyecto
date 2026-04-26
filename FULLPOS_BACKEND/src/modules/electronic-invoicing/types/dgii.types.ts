export type DgiiEnvironment = 'precertification' | 'production';

export interface DgiiEnvironmentConfig {
  environment: DgiiEnvironment;
  submitUrl: string;
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
  raw: unknown;
}

export interface DgiiTrackResultResponse {
  httpStatus: number;
  ok: boolean;
  trackId: string;
  normalizedStatus: 'accepted' | 'accepted_conditional' | 'rejected' | 'pending' | 'error';
  code?: string;
  message?: string;
  raw: unknown;
}