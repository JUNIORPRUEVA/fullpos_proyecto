import test from 'node:test';
import assert from 'node:assert/strict';
import { assertSupportedDocumentTypeCode, buildEcf, normalizeRnc } from '../utils/validation.utils';

test('validation utils normalize RNC and build e-CF values', () => {
  assert.equal(normalizeRnc('1-01-01010-1'), '101010101');
  assert.equal(buildEcf('E31', 123), 'E310000000123');
  assert.equal(assertSupportedDocumentTypeCode('34'), '34');
});