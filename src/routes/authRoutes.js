/**
 * Authentication Routes
 *
 * Implements endpoints for user registration, login, user listing,
 * and dynamic rehash policy configuration.
 */

import { Router } from 'express';
import { authService } from '../services/authService.js';
import { userStore } from '../store/userStore.js';
import { validateRegister, validateLogin } from '../middleware/validator.js';

export const authRouter = Router();

/**
 * POST /api/auth/register
 * Registers user and hashes password with ArgonCore
 */
authRouter.post('/register', validateRegister, async (req, res, next) => {
  try {
    const { username, password, profile, customOptions } = req.body;
    const result = await authService.register({
      username,
      password,
      profile,
      customOptions
    });

    res.status(201).json({
      success: true,
      message: `User '${result.user.username}' successfully registered. Password hashed using ArgonCore Argon2id.`,
      data: {
        username: result.user.username,
        hashPreview: result.hashGenerated,
        durationMs: result.durationMs,
        parametersUsed: result.parametersUsed,
        createdAt: result.user.createdAt
      }
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/auth/login
 * Verifies credentials in constant-time and performs policy rehash if needed
 */
authRouter.post('/login', validateLogin, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const result = await authService.login({ username, password });

    res.json({
      success: true,
      message: result.rehash.triggered
        ? `Authentication successful! Password hash was automatically upgraded via needsRehash() policy check.`
        : `Authentication successful! Password verified in constant time.`,
      data: result
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/auth/users
 * Lists registered users with parsed hash parameters (in-memory demo)
 */
authRouter.get('/users', (req, res) => {
  const users = userStore.getAllUsers();
  res.json({
    success: true,
    total: users.length,
    users
  });
});

/**
 * GET /api/auth/policy
 * Returns the active rehash evaluation policy
 */
authRouter.get('/policy', (req, res) => {
  const policy = authService.getPolicy();
  res.json({
    success: true,
    policy
  });
});

/**
 * PUT /api/auth/policy
 * Updates the active rehash evaluation policy
 */
authRouter.put('/policy', (req, res, next) => {
  try {
    const updated = authService.setPolicy(req.body);
    res.json({
      success: true,
      message: 'Active rehash policy updated.',
      policy: updated
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/auth/reset
 * Resets user store and re-seeds demo accounts
 */
authRouter.post('/reset', async (req, res, next) => {
  try {
    userStore.clear();
    await authService.seedDemoAccounts();
    res.json({
      success: true,
      message: 'User store reset and re-seeded with demo accounts (alice and bob).'
    });
  } catch (err) {
    next(err);
  }
});
