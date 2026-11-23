/**
 * End-to-End Authentication & Application Workflow Tests
 */

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { userStore } from '../src/store/userStore.js';
import { authService } from '../src/services/authService.js';
import { demoService } from '../src/services/demoService.js';

describe('Authentication & Security Workflows', () => {
  beforeEach(() => {
    userStore.clear();
    authService.setPolicy({ memoryCost: 1024, timeCost: 1, parallelism: 1 });
  });

  test('Registration hashes password before storage and never stores plaintext', async () => {
    const plaintextPassword = 'SuperSecretPassword789!';
    const regResult = await authService.register({
      username: 'charlie',
      password: plaintextPassword,
      profile: 'testing'
    });

    assert.equal(regResult.user.username, 'charlie');
    assert.ok(regResult.hashGenerated.startsWith('$argon2id$v=19$'));
    assert.ok(regResult.durationMs > 0);

    // Verify stored representation in userStore
    const storedUser = userStore.findByUsername('charlie');
    assert.ok(storedUser);
    assert.equal(storedUser.username, 'charlie');
    assert.ok(storedUser.passwordHash.startsWith('$argon2id$v=19$'));
    // Ensure plaintext password does NOT exist anywhere in stored object
    assert.equal(storedUser.password, undefined);
    assert.equal(storedUser.plaintextPassword, undefined);
    assert.ok(!JSON.stringify(storedUser).includes(plaintextPassword), 'Store must never contain plaintext');
  });

  test('Registration rejects duplicate usernames with conflict error', async () => {
    await authService.register({
      username: 'unique_user',
      password: 'Password123!',
      profile: 'testing'
    });

    await assert.rejects(
      async () => {
        await authService.register({
          username: 'unique_user',
          password: 'AnotherPassword456!',
          profile: 'testing'
        });
      },
      (err) => {
        assert.equal(err.statusCode, 409);
        assert.ok(err.message.includes('already taken'));
        return true;
      }
    );
  });

  test('Login succeeds with correct credentials and returns authentication info', async () => {
    await authService.register({
      username: 'dana',
      password: 'DanaPassword123!',
      profile: 'interactive'
    });

    const loginResult = await authService.login({
      username: 'dana',
      password: 'DanaPassword123!'
    });

    assert.equal(loginResult.authenticated, true);
    assert.equal(loginResult.username, 'dana');
    assert.ok(loginResult.verifyDurationMs > 0);
    assert.equal(loginResult.rehash.triggered, false);
  });

  test('Login fails for incorrect password with 401 status', async () => {
    await authService.register({
      username: 'elena',
      password: 'ElenaPassword123!',
      profile: 'testing'
    });

    await assert.rejects(
      async () => {
        await authService.login({
          username: 'elena',
          password: 'WrongPassword999!'
        });
      },
      (err) => {
        assert.equal(err.statusCode, 401);
        assert.equal(err.code, 'INVALID_CREDENTIALS');
        return true;
      }
    );
  });

  test('Login fails for unknown user with 401 status', async () => {
    await assert.rejects(
      async () => {
        await authService.login({
          username: 'non_existent_user',
          password: 'AnyPassword123!'
        });
      },
      (err) => {
        assert.equal(err.statusCode, 401);
        assert.equal(err.code, 'INVALID_CREDENTIALS');
        return true;
      }
    );
  });

  test('Transparent policy rehash triggers when stored hash is weaker than active policy', async () => {
    // 1. User registered with 256 KiB testing profile
    await authService.register({
      username: 'frank',
      password: 'FrankPassword123!',
      profile: 'testing' // m=256, t=1, p=1
    });

    const initialUser = userStore.findByUsername('frank');
    const initialHash = initialUser.passwordHash;
    assert.ok(initialHash.includes('m=256,t=1,p=1'));

    // 2. Active server policy is upgraded to 1024 KiB
    authService.setPolicy({ memoryCost: 1024, timeCost: 1, parallelism: 1 });

    // 3. User logs in -> rehash is automatically detected and executed
    const loginResult = await authService.login({
      username: 'frank',
      password: 'FrankPassword123!'
    });

    assert.equal(loginResult.authenticated, true);
    assert.equal(loginResult.rehash.triggered, true);
    assert.equal(loginResult.rehash.previousHash, initialHash);
    assert.ok(loginResult.rehash.upgradedHash.includes('m=1024,t=1,p=1'));

    // 4. Verify userStore now holds the upgraded hash and incremented rehashCount
    const updatedUser = userStore.findByUsername('frank');
    assert.equal(updatedUser.passwordHash, loginResult.rehash.upgradedHash);
    assert.equal(updatedUser.rehashCount, 1);

    // 5. Subsequent login does not trigger rehash again
    const secondLogin = await authService.login({
      username: 'frank',
      password: 'FrankPassword123!'
    });
    assert.equal(secondLogin.rehash.triggered, false);
    assert.equal(updatedUser.rehashCount, 1);
  });

  test('Demo Service parses MCF strings and checks rehash criteria accurately', () => {
    const testHash = '$argon2id$v=19$m=512,t=2,p=1$somesaltvalue$somedigestvalue';
    const parsed = demoService.parseMcfString(testHash);

    assert.equal(parsed.valid, true);
    assert.equal(parsed.type, 'argon2id');
    assert.equal(parsed.versionNum, 19);
    assert.equal(parsed.memoryCost, 512);
    assert.equal(parsed.timeCost, 2);
    assert.equal(parsed.parallelism, 1);

    const rehashCheck = demoService.checkRehash(testHash, { memoryCost: 1024, timeCost: 2, parallelism: 1 });
    assert.equal(rehashCheck.needsRehash, true);
    assert.ok(rehashCheck.reasons.length > 0);
  });
});
