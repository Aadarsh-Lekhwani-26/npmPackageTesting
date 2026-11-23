/**
 * Direct ArgonCore npm Package Verification
 *
 * Confirms that the integration directly imports and utilizes the published
 * 'argoncore' npm package (v0.1.0) according to RFC 9106.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { hash, verify, needsRehash, DEFAULTS, ARGON2_TYPES, ARGON2_VERSIONS } from 'argoncore';

const require = createRequire(import.meta.url);

describe('ArgonCore npm Package Integration', () => {
  test('resolves argoncore from node_modules', async () => {
    const resolvedPath = import.meta.resolve('argoncore');
    assert.ok(resolvedPath.includes('node_modules/argoncore'), 'Must resolve from node_modules');
    assert.ok(resolvedPath.endsWith('index.js'), 'Must point to ArgonCore entrypoint');
  });

  test('exports required cryptographic functions and constants', () => {
    assert.equal(typeof hash, 'function');
    assert.equal(typeof verify, 'function');
    assert.equal(typeof needsRehash, 'function');
    assert.ok(DEFAULTS);
    assert.equal(DEFAULTS.type, 2); // ARGON2ID
    assert.equal(DEFAULTS.version, 0x13); // 19
  });

  test('hash() generates valid RFC 9106 Modular Crypt Format (MCF) string', async () => {
    const password = 'TestSecretPassword2026!';
    const encoded = await hash(password, { memoryCost: 256, timeCost: 1, parallelism: 1 });

    assert.ok(typeof encoded === 'string');
    assert.ok(encoded.startsWith('$argon2id$v=19$m=256,t=1,p=1$'), `Expected MCF header, got: ${encoded}`);

    const parts = encoded.split('$');
    assert.equal(parts.length, 6, 'MCF format must have 6 segments delimited by $');
    assert.equal(parts[1], 'argon2id');
    assert.equal(parts[2], 'v=19');
    assert.equal(parts[3], 'm=256,t=1,p=1');
  });

  test('verify() returns true for matching password and false for mismatched password', async () => {
    const password = 'CorrectPassword#42';
    const encoded = await hash(password, { memoryCost: 256, timeCost: 1, parallelism: 1 });

    const isMatch = await verify(encoded, password);
    assert.equal(isMatch, true, 'verify() must return true for correct password');

    const isWrong = await verify(encoded, 'IncorrectPassword#42');
    assert.equal(isWrong, false, 'verify() must return false for incorrect password');
  });

  test('needsRehash() detects weaker parameters and honors upgraded policies', async () => {
    const legacyHash = await hash('test-pass', { memoryCost: 256, timeCost: 1, parallelism: 1 });

    // Target policy is higher than hash parameters -> needs rehash
    const shouldRehashHigher = needsRehash(legacyHash, { memoryCost: 1024, timeCost: 1, parallelism: 1 });
    assert.equal(shouldRehashHigher, true, 'needsRehash must return true when policy memory is higher');

    // Target policy equals hash parameters -> does not need rehash
    const shouldRehashEqual = needsRehash(legacyHash, { memoryCost: 256, timeCost: 1, parallelism: 1 });
    assert.equal(shouldRehashEqual, false, 'needsRehash must return false when policy matches');

    // Target policy has lower memory -> does not need rehash
    const shouldRehashLower = needsRehash(legacyHash, { memoryCost: 128, timeCost: 1, parallelism: 1 });
    assert.equal(shouldRehashLower, false, 'needsRehash must return false when policy is lower');
  });
});
