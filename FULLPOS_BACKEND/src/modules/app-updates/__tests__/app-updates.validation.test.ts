import assert from 'node:assert/strict';
import test from 'node:test';
import { appUpdatePolicySchema } from '../app-updates.validation';

const validPolicy = {
  projectCode: 'fullpos',
  platform: 'windows',
  version: '1.0.2',
  buildNumber: 6,
  minimumSupportedVersion: '1.0.1',
  minimumSupportedBuild: 5,
  mandatory: false,
  enabled: true,
  installerUrl: 'https://github.com/JUNIORPRUEVA/fullpos-releases/releases/download/v1.0.2/FullPOS-Setup.exe',
  installerFilename: 'FullPOS-Setup.exe',
  installerSizeBytes: 236522251,
  sha256: 'a'.repeat(64),
  releaseTitle: 'FullPOS v1.0.2',
  releaseNotes: ['Mejoras de estabilidad.'],
  publishedAt: '2026-06-12T22:00:00Z',
};

test('accepts a complete Windows update policy', () => {
  assert.equal(appUpdatePolicySchema.parse(validPolicy).buildNumber, 6);
});

test('rejects non-HTTPS installer URLs', () => {
  assert.equal(appUpdatePolicySchema.safeParse({
    ...validPolicy,
    installerUrl: 'http://github.com/FullPOS-Setup.exe',
  }).success, false);
});

test('rejects malformed semantic versions and SHA-256 values', () => {
  assert.equal(appUpdatePolicySchema.safeParse({
    ...validPolicy,
    version: '1.0',
    sha256: 'bad',
  }).success, false);
});
