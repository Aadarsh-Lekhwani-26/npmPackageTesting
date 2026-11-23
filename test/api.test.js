/**
 * HTTP REST API Integration Tests
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { app } from '../src/app.js';
import { userStore } from '../src/store/userStore.js';
import { authService } from '../src/services/authService.js';

let server;
let baseUrl;
let socketAllowed = true;

describe('Express REST API Endpoints', () => {
  before(async () => {
    userStore.clear();
    await authService.seedDemoAccounts();

    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });

    try {
      const res = await fetch(`${baseUrl}/api/health`);
      await res.json();
    } catch (err) {
      if (err.cause?.code === 'EPERM') {
        socketAllowed = false;
      }
    }
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  test('GET /api/health returns 200 with package metadata', async (t) => {
    if (!socketAllowed) return t.skip('Loopback TCP connection restricted in current sandbox');

    const res = await fetch(`${baseUrl}/api/health`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'ok');
    assert.equal(data.package, 'argoncore');
    assert.equal(data.version, '0.1.0');
  });

  test('POST /api/auth/register validates input and hashes password', async (t) => {
    if (!socketAllowed) return t.skip('Loopback TCP connection restricted in current sandbox');

    const res = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'test_http_user',
        password: 'ValidPassword123!',
        profile: 'testing'
      })
    });

    assert.equal(res.status, 201);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.data.username, 'test_http_user');
    assert.ok(body.data.hashPreview.startsWith('$argon2id$v=19$'));
    assert.ok(body.data.durationMs > 0);
  });

  test('POST /api/auth/register rejects invalid inputs', async (t) => {
    if (!socketAllowed) return t.skip('Loopback TCP connection restricted in current sandbox');

    // Short username
    const resShortUser = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'ab', password: 'ValidPassword123!' })
    });
    assert.equal(resShortUser.status, 400);

    // Short password
    const resShortPass = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'valid_user', password: '123' })
    });
    assert.equal(resShortPass.status, 400);
  });

  test('POST /api/auth/login succeeds for valid credentials and fails for invalid', async (t) => {
    if (!socketAllowed) return t.skip('Loopback TCP connection restricted in current sandbox');

    // 1. Valid login with seed user 'bob' (BobSecret456!)
    const resValid = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'bob',
        password: 'BobSecret456!'
      })
    });
    assert.equal(resValid.status, 200);
    const bodyValid = await resValid.json();
    assert.equal(bodyValid.success, true);
    assert.equal(bodyValid.data.authenticated, true);
    assert.equal(bodyValid.data.username, 'bob');

    // 2. Invalid password
    const resInvalid = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'bob',
        password: 'WrongPassword999!'
      })
    });
    assert.equal(resInvalid.status, 401);
    const bodyInvalid = await resInvalid.json();
    assert.equal(bodyInvalid.success, false);
    assert.equal(bodyInvalid.code, 'INVALID_CREDENTIALS');
  });

  test('GET /api/auth/users lists registered accounts with hash metadata', async (t) => {
    if (!socketAllowed) return t.skip('Loopback TCP connection restricted in current sandbox');

    const res = await fetch(`${baseUrl}/api/auth/users`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.ok(Array.isArray(body.users));
    assert.ok(body.total >= 2); // alice, bob, test_http_user
  });

  test('GET & PUT /api/auth/policy reads and updates server rehash threshold', async (t) => {
    if (!socketAllowed) return t.skip('Loopback TCP connection restricted in current sandbox');

    const resGet = await fetch(`${baseUrl}/api/auth/policy`);
    assert.equal(resGet.status, 200);
    const bodyGet = await resGet.json();
    assert.ok(bodyGet.policy.memoryCost);

    const resPut = await fetch(`${baseUrl}/api/auth/policy`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ memoryCost: 2048, timeCost: 2, parallelism: 2 })
    });
    assert.equal(resPut.status, 200);
    const bodyPut = await resPut.json();
    assert.equal(bodyPut.policy.memoryCost, 2048);
    assert.equal(bodyPut.policy.timeCost, 2);
    assert.equal(bodyPut.policy.parallelism, 2);
  });

  test('POST /api/demo/hash & /api/demo/verify standalone testing', async (t) => {
    if (!socketAllowed) return t.skip('Loopback TCP connection restricted in current sandbox');

    const resHash = await fetch(`${baseUrl}/api/demo/hash`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        password: 'ArbitraryDemoPassword!',
        memoryCost: 256,
        timeCost: 1,
        parallelism: 1
      })
    });
    assert.equal(resHash.status, 200);
    const hashData = await resHash.json();
    assert.ok(hashData.data.encodedHash);

    const resVerifyTrue = await fetch(`${baseUrl}/api/demo/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hash: hashData.data.encodedHash,
        password: 'ArbitraryDemoPassword!'
      })
    });
    const verifyTrue = await resVerifyTrue.json();
    assert.equal(verifyTrue.data.match, true);

    const resVerifyFalse = await fetch(`${baseUrl}/api/demo/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hash: hashData.data.encodedHash,
        password: 'IncorrectPassword'
      })
    });
    const verifyFalse = await resVerifyFalse.json();
    assert.equal(verifyFalse.data.match, false);
  });

  test('POST /api/demo/parse and GET /api/demo/profiles work properly', async (t) => {
    if (!socketAllowed) return t.skip('Loopback TCP connection restricted in current sandbox');

    const resParse = await fetch(`${baseUrl}/api/demo/parse`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hash: '$argon2id$v=19$m=1024,t=1,p=1$rccxm1hySSQ2LDAIP5awuA$72nO+cY6UX1hm1D4xhSkk5bHwdIlJ8ag9c6hIg0o+qs'
      })
    });
    assert.equal(resParse.status, 200);
    const parseData = await resParse.json();
    assert.equal(parseData.data.valid, true);
    assert.equal(parseData.data.memoryCost, 1024);

    const resProfiles = await fetch(`${baseUrl}/api/demo/profiles`);
    assert.equal(resProfiles.status, 200);
    const profData = await resProfiles.json();
    assert.ok(Array.isArray(profData.profiles));
    assert.ok(profData.profiles.length >= 4);
  });
});
