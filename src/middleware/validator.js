/**
 * Input Validation Middleware
 */

export function validateRegister(req, res, next) {
  const { username, password } = req.body || {};

  if (!username || typeof username !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Username is required and must be a string.'
    });
  }

  const trimmedUser = username.trim();
  if (trimmedUser.length < 3 || trimmedUser.length > 30) {
    return res.status(400).json({
      success: false,
      error: 'Username must be between 3 and 30 characters.'
    });
  }

  const usernameRegex = /^[a-zA-Z0-9_-]+$/;
  if (!usernameRegex.test(trimmedUser)) {
    return res.status(400).json({
      success: false,
      error: 'Username may only contain letters, numbers, hyphens, and underscores.'
    });
  }

  if (!password || typeof password !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Password is required and must be a string.'
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      success: false,
      error: 'Password must be at least 6 characters long.'
    });
  }

  if (password.length > 256) {
    return res.status(400).json({
      success: false,
      error: 'Password cannot exceed 256 characters.'
    });
  }

  next();
}

export function validateLogin(req, res, next) {
  const { username, password } = req.body || {};

  if (!username || typeof username !== 'string' || !username.trim()) {
    return res.status(400).json({
      success: false,
      error: 'Username is required.'
    });
  }

  if (!password || typeof password !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Password is required.'
    });
  }

  next();
}
