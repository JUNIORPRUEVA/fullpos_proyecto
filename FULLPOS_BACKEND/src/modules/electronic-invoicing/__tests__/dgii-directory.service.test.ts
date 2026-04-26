import test from 'node:test';
import assert from 'node:assert/strict';
import { ensureFeTestEnv } from './test-helpers';

ensureFeTestEnv();

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