import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'path';
import { spawnSync } from 'node:child_process';

const envModulePath = path.join(__dirname, '../../../config/env');

const baseEnv = {
  NODE_ENV: 'test',
  PORT: '4000',
  DATABASE_URL: 'https://example.test/db',
  JWT_ACCESS_SECRET: 'test-jwt-access-secret-1234',
  JWT_REFRESH_SECRET: 'test-jwt-refresh-secret-1234',
};

function loadEnvInChild(overrides: Record<string, string | undefined>) {
  const result = spawnSync(
    process.execPath,
    [
      '-e',
      `try { const env = require(${JSON.stringify(envModulePath)}).default; console.log(JSON.stringify({ ok: true, feSeed: env.FE_SEED_TTL_SECONDS, feToken: env.FE_PUBLIC_TOKEN_TTL_SECONDS })); } catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exit(1); }`,
    ],
    {
      env: {
        ...process.env,
        ...baseEnv,
        ...overrides,
      },
      encoding: 'utf8',
    },
  );

  return result;
}

test('env validation allows startup without FE master key and uses FE defaults', () => {
  const result = loadEnvInChild({
    FE_MASTER_ENCRYPTION_KEY: undefined,
    FE_SEED_TTL_SECONDS: undefined,
    FE_PUBLIC_TOKEN_TTL_SECONDS: undefined,
  });

  assert.equal(result.status, 0, result.stderr);
  const payload = JSON.parse(result.stdout.trim()) as {
    ok: boolean;
    feSeed: number;
    feToken: number;
  };
  assert.equal(payload.ok, true);
  assert.equal(payload.feSeed, 300);
  assert.equal(payload.feToken, 300);
});

test('env validation rejects FE seed TTL below minimum boundary', () => {
  const result = loadEnvInChild({ FE_SEED_TTL_SECONDS: '29' });

  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}${result.stdout}`, /Number must be greater than or equal to 30/i);
});

test('env validation rejects FE public token TTL above maximum boundary', () => {
  const result = loadEnvInChild({ FE_PUBLIC_TOKEN_TTL_SECONDS: '86401' });

  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}${result.stdout}`, /Number must be less than or equal to 86400/i);
});