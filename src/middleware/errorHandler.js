/**
 * Centralized Error Handler Middleware
 *
 * Catches uncaught synchronous and asynchronous route exceptions.
 * Never leaks raw stack traces or internal secrets to client.
 */

export function errorHandler(err, req, res, next) { // eslint-disable-line no-unused-vars
  const status = err.statusCode || (res.statusCode >= 400 ? res.statusCode : 500);

  // Keep passwords, salts, and secrets out of server logs
  const logMessage = `[API Error] ${req.method} ${req.url} (${status}): ${err.message}`;
  if (status >= 500) {
    console.error(logMessage);
  } else {
    console.warn(logMessage);
  }

  res.status(status).json({
    success: false,
    error: err.message || 'An unexpected error occurred.',
    code: err.code || (status === 401 ? 'UNAUTHORIZED' : status === 409 ? 'CONFLICT' : 'INTERNAL_ERROR')
  });
}
