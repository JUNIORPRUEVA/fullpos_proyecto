import assert from 'node:assert/strict';
import test from 'node:test';
import express from 'express';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import env from '../../config/env';
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
    createReleasePolicyAuthGuard(releaseKey, releaseKey),
    (req, res) => res.json({ method: req.releasePolicyAuthMethod }),
  );
  return app;
}

test('FullCredit release key is scoped to the FullCredit route', async () => {
  const fullPosKey = 'fullpos-release-key-with-32-characters';
  const fullCreditKey = 'fullcredit-release-key-with-32-characters';
  const app = express();
  const guard = createReleasePolicyAuthGuard(fullPosKey, fullCreditKey);
  app.put('/fullpos/windows', guard, (_req, res) => res.sendStatus(200));
  app.put('/fullcredit/android', guard, (_req, res) => res.sendStatus(200));

  await request(app)
    .put('/fullcredit/android')
    .set('X-Release-Key', fullCreditKey)
    .expect(200);
  await request(app)
    .put('/fullpos/windows')
    .set('X-Release-Key', fullCreditKey)
    .expect(401);
});

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
    env.JWT_ACCESS_SECRET,
    { expiresIn: '5m' },
  );

  const accepted = await request(app)
    .put('/policy')
    .set('Authorization', `Bearer ${token}`)
    .expect(200);
  assert.equal(accepted.body.method, 'admin_session');
});

test('missing FullCredit key disables only release-key authentication', async () => {
  const app = express();
  app.put(
    '/fullcredit/android',
    createReleasePolicyAuthGuard(
      'fullpos-release-key-with-32-characters',
      undefined,
    ),
    (_req, res) => res.sendStatus(200),
  );

  await request(app)
    .put('/fullcredit/android')
    .set('X-Release-Key', 'fullcredit-release-key-with-32-characters')
    .expect(401);

  const token = jwt.sign(
    {
      id: 1,
      companyId: 1,
      username: 'release-owner',
      role: 'owner',
    },
    env.JWT_ACCESS_SECRET,
    { expiresIn: '5m' },
  );

  await request(app)
    .put('/fullcredit/android')
    .set('Authorization', `Bearer ${token}`)
    .expect(200);
});
