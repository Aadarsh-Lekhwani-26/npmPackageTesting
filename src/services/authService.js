/**
 * Authentication Service
 *
 * Uses the published npm package 'argoncore' for all cryptographic operations:
 * - hash() for password hashing
 * - verify() for constant-time credential checking
 * - needsRehash() for algorithm parameter policy evaluation
 */

import { hash, verify, needsRehash, DEFAULTS } from 'argoncore';
import { userStore } from '../store/userStore.js';
import { PROFILES, config } from '../config.js';

class AuthService {
  constructor() {
    this.activePolicy = { ...config.activePolicy };
  }

  /**
   * Returns current active policy used for rehashing decisions.
   */
  getPolicy() {
    return { ...this.activePolicy };
  }

  /**
   * Updates the server's minimum security policy for rehashing demonstration.
   * @param {Object} newPolicy
   */
  setPolicy(newPolicy) {
    if (newPolicy.memoryCost !== undefined) {
      const m = parseInt(newPolicy.memoryCost, 10);
      if (isNaN(m) || m < 8) throw new Error('memoryCost must be at least 8 KiB');
      this.activePolicy.memoryCost = m;
    }
    if (newPolicy.timeCost !== undefined) {
      const t = parseInt(newPolicy.timeCost, 10);
      if (isNaN(t) || t < 1) throw new Error('timeCost must be at least 1 iteration');
      this.activePolicy.timeCost = t;
    }
    if (newPolicy.parallelism !== undefined) {
      const p = parseInt(newPolicy.parallelism, 10);
      if (isNaN(p) || p < 1) throw new Error('parallelism must be at least 1 lane');
      this.activePolicy.parallelism = p;
    }
    return { ...this.activePolicy };
  }

  /**
   * Resolves options based on a profile name or custom options.
   * Clamps parameters within safe bounds for the demo runtime.
   */
  resolveHashOptions(profileName, customOptions = {}) {
    let options = {};

    if (profileName && PROFILES[profileName]) {
      const preset = PROFILES[profileName];
      options = {
        memoryCost: preset.memoryCost,
        timeCost: preset.timeCost,
        parallelism: preset.parallelism
      };
    } else {
      // Fallback to active policy or custom options
      options = {
        memoryCost: customOptions.memoryCost || this.activePolicy.memoryCost,
        timeCost: customOptions.timeCost || this.activePolicy.timeCost,
        parallelism: customOptions.parallelism || this.activePolicy.parallelism
      };
    }

    // Guard: Prevent excessive allocations in browser/demo contexts
    if (options.memoryCost > 65536) options.memoryCost = 65536;
    if (options.memoryCost < 16) options.memoryCost = 16;
    if (options.timeCost > 10) options.timeCost = 10;
    if (options.timeCost < 1) options.timeCost = 1;
    if (options.parallelism > 8) options.parallelism = 8;
    if (options.parallelism < 1) options.parallelism = 1;

    return options;
  }

  /**
   * Registers a new user with Argon2id password hashing.
   *
   * @param {Object} params
   * @param {string} params.username
   * @param {string} params.password
   * @param {string} [params.profile]
   * @param {Object} [params.customOptions]
   * @returns {Promise<Object>} Safe registration result
   */
  async register({ username, password, profile, customOptions }) {
    if (!username || typeof username !== 'string' || username.trim().length < 3) {
      throw new Error('Username must be at least 3 characters long.');
    }
    if (!password || typeof password !== 'string' || password.length < 6) {
      throw new Error('Password must be at least 6 characters long.');
    }

    if (userStore.hasUser(username)) {
      const err = new Error(`Username '${username}' is already taken.`);
      err.statusCode = 409;
      throw err;
    }

    const hashOptions = this.resolveHashOptions(profile, customOptions);

    const startTime = performance.now();
    // Invoke ArgonCore npm package hash()
    const passwordHash = await hash(password, hashOptions);
    const durationMs = Math.round((performance.now() - startTime) * 100) / 100;

    const user = userStore.createUser(username, passwordHash, {
      profileUsed: profile || 'custom'
    });

    return {
      user,
      hashGenerated: passwordHash,
      durationMs,
      parametersUsed: hashOptions
    };
  }

  /**
   * Authenticates a user and performs transparent rehashing if policy upgraded.
   *
   * @param {Object} params
   * @param {string} params.username
   * @param {string} params.password
   * @returns {Promise<Object>} Authentication result
   */
  async login({ username, password }) {
    if (!username || !password) {
      throw new Error('Username and password are required.');
    }

    const user = userStore.findByUsername(username);
    if (!user) {
      const err = new Error('Invalid username or password.');
      err.statusCode = 401;
      err.code = 'INVALID_CREDENTIALS';
      throw err;
    }

    // 1. Verify candidate password against stored Argon2id hash in constant time
    const startTime = performance.now();
    const isValid = await verify(user.passwordHash, password);
    const verifyDurationMs = Math.round((performance.now() - startTime) * 100) / 100;

    if (!isValid) {
      const err = new Error('Invalid username or password.');
      err.statusCode = 401;
      err.code = 'INVALID_CREDENTIALS';
      throw err;
    }

    userStore.recordLogin(username);

    // 2. Evaluate if the stored hash parameters meet current server security policy
    const rehashRequired = needsRehash(user.passwordHash, this.activePolicy);
    let rehashInfo = null;

    if (rehashRequired) {
      const rehashStartTime = performance.now();
      // Generate upgraded hash with target policy parameters
      const upgradedHash = await hash(password, this.activePolicy);
      const rehashDurationMs = Math.round((performance.now() - rehashStartTime) * 100) / 100;

      const previousHash = user.passwordHash;
      userStore.updatePasswordHash(username, upgradedHash);

      rehashInfo = {
        triggered: true,
        previousHash,
        upgradedHash,
        newPolicy: { ...this.activePolicy },
        rehashDurationMs
      };
    } else {
      rehashInfo = {
        triggered: false,
        activePolicy: { ...this.activePolicy }
      };
    }

    return {
      authenticated: true,
      username: user.username,
      verifyDurationMs,
      storedHash: user.passwordHash,
      rehash: rehashInfo
    };
  }

  /**
   * Seeds demo accounts for immediate hands-on testing.
   */
  async seedDemoAccounts() {
    // Check if already seeded
    if (userStore.getAllUsers().length > 0) return;

    // Seed account 1: 'alice' with legacy/testing hash (256 KiB) to demonstrate needsRehash()
    const aliceHash = await hash('AlicePass123!', { memoryCost: 256, timeCost: 1, parallelism: 1 });
    userStore.createUser('alice', aliceHash, { profileUsed: 'testing' });

    // Seed account 2: 'bob' with modern interactive hash (1024 KiB)
    const bobHash = await hash('BobSecret456!', { memoryCost: 1024, timeCost: 1, parallelism: 1 });
    userStore.createUser('bob', bobHash, { profileUsed: 'interactive' });
  }
}

export const authService = new AuthService();
