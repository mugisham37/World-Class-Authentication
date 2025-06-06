import { authenticate, optionalAuthenticate } from './auth.middleware';

import { correlationIdMiddleware, getCurrentCorrelationId } from './correlation-id.middleware';

import {
  csrfProtection,
  apiCSRFProtection,
  csrfTokenProvider,
  getCSRFToken,
  CSRFError,
} from './csrf-protection.middleware';

import {
  deviceFingerprint,
  createDeviceFingerprintMiddleware,
} from './device-fingerprint.middleware';

import {
  errorHandler,
  notFoundHandler,
  methodNotAllowedHandler,
} from './error-handling.middleware';

import {
  validate,
  validateBody,
  validateQuery,
  validateParams,
  validateHeaders,
  validateRequest,
} from './input-validation.middleware';

import {
  createRateLimiter,
  defaultRateLimiter,
  strictRateLimiter,
  authRateLimiter,
  apiRateLimiter,
  userRateLimiter,
} from './rate-limiting.middleware';

import {
  requestLogger,
  minimalRequestLogger,
  detailedRequestLogger,
  apiRequestLogger,
  createRequestLoggerMiddleware,
} from './request-logger.middleware';

import {
  securityHeaders,
  apiSecurityHeaders,
  staticSecurityHeaders,
  createSecurityHeadersMiddleware,
} from './security-headers.middleware';

import {
  updateSessionActivity,
  checkSessionExpiration,
  validateSession,
  checkSessionDevice,
} from './session.middleware';

/**
 * Middleware execution order
 * 1. correlationIdMiddleware - Adds correlation ID for request tracing
 * 2. securityHeaders - Adds security headers to responses
 * 3. csrfProtection - Protects against CSRF attacks
 * 4. defaultRateLimiter - Limits request rate
 * 5. deviceFingerprint - Adds device fingerprint to request
 * 6. requestLogger - Logs request information
 * 7. authenticate - Authenticates user
 * 8. validateSession - Validates user session
 * 9. checkSessionExpiration - Checks if session has expired
 * 10. checkSessionDevice - Verifies request is from same device
 * 11. updateSessionActivity - Updates session activity
 * 12. validate - Validates request data
 * 13. Route handlers
 * 14. errorHandler - Handles errors
 * 15. notFoundHandler - Handles 404 errors
 */

/**
 * Common middleware stack
 * Used for all routes
 */
export const commonMiddleware = [
  correlationIdMiddleware,
  securityHeaders,
  csrfProtection,
  defaultRateLimiter,
  deviceFingerprint,
  requestLogger,
];

/**
 * API middleware stack
 * Used for API routes
 */
export const apiMiddleware = [
  correlationIdMiddleware,
  apiSecurityHeaders,
  apiCSRFProtection,
  apiRateLimiter,
  deviceFingerprint,
  apiRequestLogger,
];

/**
 * Authentication middleware stack
 * Used for routes that require authentication
 */
export const authMiddleware = [
  ...commonMiddleware,
  authenticate,
  validateSession,
  checkSessionExpiration,
  checkSessionDevice,
  updateSessionActivity,
];

/**
 * Optional authentication middleware stack
 * Used for routes that support but don't require authentication
 */
export const optionalAuthMiddleware = [
  ...commonMiddleware,
  optionalAuthenticate,
  updateSessionActivity,
];

/**
 * Error handling middleware stack
 * Used at the end of the middleware chain
 */
export const errorMiddleware = [errorHandler, notFoundHandler];

// Export all middleware functions
export {
  // Auth middleware
  authenticate,
  optionalAuthenticate,

  // Correlation ID middleware
  correlationIdMiddleware,
  getCurrentCorrelationId,

  // CSRF protection middleware
  csrfProtection,
  apiCSRFProtection,
  csrfTokenProvider,
  getCSRFToken,
  CSRFError,

  // Device fingerprint middleware
  deviceFingerprint,
  createDeviceFingerprintMiddleware,

  // Error handling middleware
  errorHandler,
  notFoundHandler,
  methodNotAllowedHandler,

  // Input validation middleware
  validate,
  validateBody,
  validateQuery,
  validateParams,
  validateHeaders,
  validateRequest,

  // Rate limiting middleware
  createRateLimiter,
  defaultRateLimiter,
  strictRateLimiter,
  authRateLimiter,
  apiRateLimiter,
  userRateLimiter,

  // Request logger middleware
  requestLogger,
  minimalRequestLogger,
  detailedRequestLogger,
  apiRequestLogger,
  createRequestLoggerMiddleware,

  // Security headers middleware
  securityHeaders,
  apiSecurityHeaders,
  staticSecurityHeaders,
  createSecurityHeadersMiddleware,

  // Session middleware
  updateSessionActivity,
  checkSessionExpiration,
  validateSession,
  checkSessionDevice,
};
