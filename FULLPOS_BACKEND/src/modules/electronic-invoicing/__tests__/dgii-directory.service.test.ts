import test from 'node:test';
import assert from 'node:assert/strict';

process.env.FE_MASTER_ENCRYPTION_KEY = process.env.FE_MASTER_ENCRYPTION_KEY ?? 'test-master-key-1234567890-abcdef';
process.env.FE_SEED_TTL_SECONDS = process.env.FE_SEED_TTL_SECONDS ?? '300';
process.env.FE_PUBLIC_TOKEN_TTL_SECONDS = process.env.FE_PUBLIC_TOKEN_TTL_SECONDS ?? '300';
process.env.DGII_REQUEST_TIMEOUT_MS = process.env.DGII_REQUEST_TIMEOUT_MS ?? '5000';
process.env.DGII_REQUEST_MAX_RETRIES = process.env.DGII_REQUEST_MAX_RETRIES ?? '1';
process.env.DGII_HTTP_USER_AGENT = process.env.DGII_HTTP_USER_AGENT ?? 'FULLPOS-Test';
process.env.DGII_PRECERT_SUBMIT_URL = process.env.DGII_PRECERT_SUBMIT_URL ?? 'https://precert.example.com/submit';
process.env.DGII_PRECERT_RESULT_URL_TEMPLATE = process.env.DGII_PRECERT_RESULT_URL_TEMPLATE ?? 'https://precert.example.com/result/{trackId}';
process.env.DGII_PRODUCTION_SUBMIT_URL = process.env.DGII_PRODUCTION_SUBMIT_URL ?? 'https://prod.example.com/submit';
process.env.DGII_PRODUCTION_RESULT_URL_TEMPLATE = process.env.DGII_PRODUCTION_RESULT_URL_TEMPLATE ?? 'https://prod.example.com/result/{trackId}';

const { DgiiDirectoryService } = require('../services/dgii-directory.service');

test('DgiiDirectoryService replaces trackId placeholders', () => {
  const service = new DgiiDirectoryService();

  assert.equal(
    service.buildTrackResultUrl('https://dgii.local/result/{trackId}', 'TRK/123'),
    'https://dgii.local/result/TRK%2F123',
  );
  assert.equal(
    service.buildTrackResultUrl('https://dgii.local/result/:trackId', 'ABC 999'),
    'https://dgii.local/result/ABC%20999',
  );
});

test('DgiiDirectoryService appends trackId as query parameter when no placeholder exists', () => {
  const service = new DgiiDirectoryService();
  const result = service.buildTrackResultUrl('https://dgii.local/result?foo=1', 'T-1');

  assert.equal(result, 'https://dgii.local/result?foo=1&trackId=T-1');
});