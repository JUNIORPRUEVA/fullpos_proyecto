import assert from 'node:assert/strict';
import test from 'node:test';
import express from 'express';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import {
  createReleasePolicyAuthGuard,
  timingSafeSecretEqual,
} from '../releasePolicyAuthGuard';

test('timingSafeSecretEqual accepts an exact release key', () => {
  const key = 'release-key-with-at-least-32-characters';
  assert.equal(timingSafeSecretEqual(key, key), true);
});

test('timingSafeSecretEqual rejects different values and lengths safely', () => {
  assert.equal(
    timingSafeSecretEqual(
      'release-key-with-at-least-32-characters',
      'release-key-with-at-least-32-characterX',
    ),
    false,
  );
  assert.equal(timingSafeSecretEqual('short', 'a-much-longer-secret'), false);
});

function createTestApp(releaseKey: string) {
  const app = express();
  app.put(
    '/policy',
    createReleasePolicyAuthGuard(releaseKey),
    (req, res) => res.json({ method: req.releasePolicyAuthMethod }),
  );
  return app;
}

test('release policy guard accepts only the exact X-Release-Key', async () => {
  const key = 'release-key-with-at-least-32-characters';
  const app = createTestApp(key);

  const accepted = await request(app)
    .put('/policy')
    .set('X-Release-Key', key)
    .expect(200);
  assert.equal(accepted.body.method, 'release_key');

  await request(app)
    .put('/policy')
    .set('X-Release-Key', `${key}x`)
    .expect(401);
  await request(app).put('/policy').set('X-Release-Key', '   ').expect(401);
});

test('release policy guard preserves admin/owner JWT authorization', async () => {
  const app = createTestApp('release-key-with-at-least-32-characters');
  const token = jwt.sign(
    {
      id: 1,
      companyId: 1,
      username: 'release-admin',
      role: 'admin',
    },
    'test-access-secret-long-enough',
    { expiresIn: '5m' },
  );

  const accepted = await request(app)
    .put('/policy')
    .set('Authorization', `Bearer ${token}`)
    .expect(200);
  assert.equal(accepted.body.method, 'admin_session');
});
