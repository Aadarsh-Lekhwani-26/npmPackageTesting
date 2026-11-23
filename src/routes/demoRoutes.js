/**
 * Security & Feature Demo Routes
 *
 * Standalone endpoints for exploring ArgonCore capabilities:
 * - Direct password hashing with custom parameter profiles
 * - Password verification against MCF strings
 * - Policy rehash inspection via needsRehash()
 * - Modular Crypt Format (MCF) dissection
 */

import { Router } from 'express';
import { demoService } from '../services/demoService.js';

export const demoRouter = Router();

/**
 * POST /api/demo/hash
 * Hashes an arbitrary password with ArgonCore
 */
demoRouter.post('/hash', async (req, res, next) => {
  try {
    const { password, memoryCost, timeCost, parallelism } = req.body;
    const result = await demoService.hashPassword(password, {
      memoryCost,
      timeCost,
      parallelism
    });

    res.json({
      success: true,
      data: result
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/demo/verify
 * Tests a candidate password against an encoded MCF hash
 */
demoRouter.post('/verify', async (req, res, next) => {
  try {
    const { hash: encodedHash, password } = req.body;
    const result = await demoService.verifyPassword(encodedHash, password);

    res.json({
      success: true,
      data: result
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/demo/rehash-check
 * Evaluates whether an encoded hash satisfies target parameter policies
 */
demoRouter.post('/rehash-check', (req, res, next) => {
  try {
    const { hash: encodedHash, targetPolicy } = req.body;
    const result = demoService.checkRehash(encodedHash, targetPolicy);

    res.json({
      success: true,
      data: result
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/demo/parse
 * Parses an MCF string into component tokens
 */
demoRouter.post('/parse', (req, res, next) => {
  try {
    const { hash: encodedHash } = req.body;
    const result = demoService.parseMcfString(encodedHash);

    res.json({
      success: true,
      data: result
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/demo/profiles
 * Returns recommended Argon2 parameter profiles
 */
demoRouter.get('/profiles', (req, res) => {
  const profiles = demoService.getProfiles();
  res.json({
    success: true,
    profiles
  });
});
