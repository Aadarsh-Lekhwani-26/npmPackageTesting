/**
 * Demonstration Service for ArgonCore Feature Exploration
 *
 * Provides dedicated inspection, verification, and policy testing utilities
 * without requiring account persistence.
 */

import { hash, verify, needsRehash, DEFAULTS } from 'argoncore';
import { PROFILES } from '../config.js';

class DemoService {
  /**
   * Hashes an arbitrary password with user-defined parameters.
   */
  async hashPassword(password, options = {}) {
    if (!password || typeof password !== 'string') {
      throw new Error('Password must be a non-empty string.');
    }

    const memoryCost = parseInt(options.memoryCost || 1024, 10);
    const timeCost = parseInt(options.timeCost || 1, 10);
    const parallelism = parseInt(options.parallelism || 1, 10);

    const safeOptions = {
      memoryCost: Math.min(Math.max(memoryCost, 16), 65536),
      timeCost: Math.min(Math.max(timeCost, 1), 10),
      parallelism: Math.min(Math.max(parallelism, 1), 8)
    };

    const startTime = performance.now();
    const encodedHash = await hash(password, safeOptions);
    const durationMs = Math.round((performance.now() - startTime) * 100) / 100;

    const parsed = this.parseMcfString(encodedHash);

    return {
      encodedHash,
      durationMs,
      optionsUsed: safeOptions,
      parsed
    };
  }

  /**
   * Verifies candidate password against any supplied Argon2 MCF hash.
   */
  async verifyPassword(encodedHash, candidatePassword) {
    if (!encodedHash || typeof encodedHash !== 'string') {
      throw new Error('Encoded hash string is required.');
    }
    if (candidatePassword === undefined || candidatePassword === null) {
      throw new Error('Candidate password is required.');
    }

    const startTime = performance.now();
    let isValid = false;
    let error = null;

    try {
      isValid = await verify(encodedHash, String(candidatePassword));
    } catch (err) {
      error = err.message;
    }
    const durationMs = Math.round((performance.now() - startTime) * 100) / 100;

    return {
      match: isValid,
      durationMs,
      error
    };
  }

  /**
   * Tests whether an MCF hash needs rehashing against target policy criteria.
   */
  checkRehash(encodedHash, targetPolicy = {}) {
    if (!encodedHash || typeof encodedHash !== 'string') {
      throw new Error('Encoded hash string is required.');
    }

    const desiredOptions = {
      memoryCost: parseInt(targetPolicy.memoryCost || 1024, 10),
      timeCost: parseInt(targetPolicy.timeCost || 1, 10),
      parallelism: parseInt(targetPolicy.parallelism || 1, 10),
      version: targetPolicy.version ? parseInt(targetPolicy.version, 10) : 0x13
    };

    const needs = needsRehash(encodedHash, desiredOptions);
    const parsed = this.parseMcfString(encodedHash);

    // Provide detailed diagnostics on which parameters caused rehash
    const reasons = [];
    if (parsed.memoryCost !== undefined && parsed.memoryCost < desiredOptions.memoryCost) {
      reasons.push(`Memory cost (${parsed.memoryCost} KiB) is lower than policy (${desiredOptions.memoryCost} KiB)`);
    }
    if (parsed.timeCost !== undefined && parsed.timeCost < desiredOptions.timeCost) {
      reasons.push(`Time cost (${parsed.timeCost} iterations) is lower than policy (${desiredOptions.timeCost})`);
    }
    if (parsed.parallelism !== undefined && parsed.parallelism < desiredOptions.parallelism) {
      reasons.push(`Parallelism (${parsed.parallelism} lanes) is lower than policy (${desiredOptions.parallelism})`);
    }
    if (parsed.versionNum !== undefined && parsed.versionNum < desiredOptions.version) {
      reasons.push(`Specification version (v=${parsed.versionNum}) is older than policy (v=${desiredOptions.version})`);
    }

    return {
      needsRehash: needs,
      reasons,
      parsedCurrent: parsed,
      desiredPolicy: desiredOptions
    };
  }

  /**
   * Dissects an MCF string into individual components with cryptographic annotations.
   */
  parseMcfString(mcfString) {
    if (!mcfString || typeof mcfString !== 'string') {
      return { valid: false, error: 'Empty or invalid hash string' };
    }

    const parts = mcfString.split('$');
    // Expected format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
    if (parts.length < 6) {
      return { valid: false, error: 'Malformed MCF string structure' };
    }

    const [, type, versionStr, paramsStr, saltBase64, digestBase64] = parts;
    const versionNum = parseInt(versionStr.replace('v=', ''), 10);

    const params = {};
    paramsStr.split(',').forEach(pair => {
      const [k, v] = pair.split('=');
      if (k && v) params[k] = parseInt(v, 10);
    });

    const memoryKiB = params.m || 0;
    const memoryMiB = Math.round((memoryKiB / 1024) * 10) / 10;

    return {
      valid: true,
      raw: mcfString,
      components: {
        type: {
          token: `$${type}$`,
          value: type,
          description: 'Argon2 algorithm variant (argon2id combines data-independent and data-dependent memory passes to resist side-channel & GPU attacks).'
        },
        version: {
          token: `$${versionStr}$`,
          value: versionNum,
          description: `Specification version number (${versionNum === 19 ? '0x13 / RFC 9106 current standard' : '0x10 legacy'}).`
        },
        parameters: {
          token: `$${paramsStr}$`,
          memoryCost: memoryKiB,
          memoryFormatted: `${memoryKiB} KiB (${memoryMiB} MiB)`,
          timeCost: params.t,
          parallelism: params.p,
          description: `Cost metrics: m=${memoryKiB} KiB memory buffer, t=${params.t} iterations, p=${params.p} parallel computation lanes.`
        },
        salt: {
          token: `$${saltBase64}$`,
          value: saltBase64,
          description: 'Cryptographic salt in unpadded Base64 (RFC 4648). Prevents precomputed dictionary and rainbow table attacks.'
        },
        digest: {
          token: `$${digestBase64}`,
          value: digestBase64,
          description: 'Calculated password authentication tag in unpadded Base64 derived from the memory matrix.'
        }
      },
      memoryCost: memoryKiB,
      timeCost: params.t,
      parallelism: params.p,
      versionNum,
      type
    };
  }

  /**
   * Returns security parameter profiles list.
   */
  getProfiles() {
    return Object.values(PROFILES);
  }
}

export const demoService = new DemoService();
