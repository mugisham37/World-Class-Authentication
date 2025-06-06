import type { Request, Response, NextFunction } from 'express';
import { randomBytes } from 'crypto';
import { logger } from '../../infrastructure/logging/logger';
import { getCurrentCorrelationId } from './correlation-id.middleware';
import { env } from '../../config/environment';
import { AppError } from '../../utils/error-handling';

/**
 * CSRF error
 */
export class CSRFError extends AppError {
  constructor(message: string, code: string = 'CSRF_ERROR') {
    super(message, code);
  }
}

/**
 * CSRF protection options
 */
interface CSRFProtectionOptions {
  // Cookie name for CSRF token
  cookieName: string;
  // Header name for CSRF token
  headerName: string;
  // Whether to enable CSRF protection
  enabled: boolean;
  // Whether to ignore GET, HEAD, OPTIONS requests
  ignoreMethods: string[];
  // Whether to ignore specific paths
  ignorePaths: string[];
  // Cookie options
  cookie: {
    // Whether the cookie is HTTP only
    httpOnly: boolean;
    // Whether the cookie is secure
    secure: boolean;
    // Same site policy
    sameSite: boolean | 'lax' | 'strict' | 'none';
    // Cookie path
    path: string;
    // Cookie max age in milliseconds
    maxAge: number;
  };
}

/**
 * Default CSRF protection options
 */
const defaultOptions: CSRFProtectionOptions = {
  cookieName: 'XSRF-TOKEN',
  headerName: 'X-XSRF-TOKEN',
  enabled: true,
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
  ignorePaths: ['/api/health', '/api/metrics', '/api/webhook'],
  cookie: {
    httpOnly: false, // Must be accessible from JavaScript
    secure: env.isProduction(),
    sameSite: 'lax',
    path: '/',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
};

/**
 * Generate CSRF token
 * @returns CSRF token
 */
function generateCSRFToken(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Create CSRF protection middleware with custom options
 * @param options CSRF protection options
 * @returns CSRF protection middleware
 */
export function createCSRFProtectionMiddleware(options: Partial<CSRFProtectionOptions> = {}) {
  // Merge options with defaults
  const mergedOptions: CSRFProtectionOptions = { ...defaultOptions, ...options };

  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const correlationId =
        getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

      // Skip CSRF protection if disabled
      if (!mergedOptions.enabled) {
        return next();
      }

      // Skip CSRF protection for ignored methods
      if (mergedOptions.ignoreMethods.includes(req.method)) {
        // For GET requests, set the CSRF token cookie if it doesn't exist
        if (req.method === 'GET' && !req.cookies[mergedOptions.cookieName]) {
          const token = generateCSRFToken();
          res.cookie(mergedOptions.cookieName, token, mergedOptions.cookie);

          // Store token in request for use in templates
          (req as any).csrfToken = token;

          logger.debug(`[${correlationId}] CSRF token generated`, {
            path: req.path,
            method: req.method,
            correlationId,
          });
        }

        return next();
      }

      // Skip CSRF protection for ignored paths
      if (mergedOptions.ignorePaths.some(path => req.path.startsWith(path))) {
        return next();
      }

      // Get CSRF token from cookie
      const cookieToken = req.cookies[mergedOptions.cookieName];

      // Get CSRF token from header
      const headerToken = req.headers[mergedOptions.headerName.toLowerCase()] as string;

      // Validate CSRF token
      if (!cookieToken || !headerToken || cookieToken !== headerToken) {
        logger.warn(`[${correlationId}] CSRF token validation failed`, {
          path: req.path,
          method: req.method,
          ip: req.ip,
          correlationId,
          hasCookieToken: !!cookieToken,
          hasHeaderToken: !!headerToken,
          tokensMatch: cookieToken === headerToken,
        });

        return next(new CSRFError('CSRF token validation failed'));
      }

      // CSRF token is valid
      logger.debug(`[${correlationId}] CSRF token validated`, {
        path: req.path,
        method: req.method,
        correlationId,
      });

      // Generate a new token for the next request
      const newToken = generateCSRFToken();
      res.cookie(mergedOptions.cookieName, newToken, mergedOptions.cookie);

      // Store token in request for use in templates
      (req as any).csrfToken = newToken;

      next();
    } catch (error) {
      logger.error('CSRF protection middleware error', {
        error,
        correlationId: getCurrentCorrelationId(),
      });
      next(new CSRFError('CSRF protection error'));
    }
  };
}

/**
 * Default CSRF protection middleware
 */
export const csrfProtection = createCSRFProtectionMiddleware();

/**
 * API CSRF protection middleware
 * Stricter CSRF protection for API routes
 */
export const apiCSRFProtection = createCSRFProtectionMiddleware({
  cookieName: 'API-XSRF-TOKEN',
  headerName: 'X-API-XSRF-TOKEN',
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
  ignorePaths: ['/api/health', '/api/metrics', '/api/webhook'],
  cookie: {
    httpOnly: false,
    secure: true,
    sameSite: 'strict',
    path: '/api',
    maxAge: 1 * 60 * 60 * 1000, // 1 hour
  },
});

/**
 * CSRF token provider middleware
 * Only sets the CSRF token cookie without validating
 */
export const csrfTokenProvider = (req: Request, res: Response, next: NextFunction): void => {
  try {
    const correlationId =
      getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

    // Generate a new token
    const token = generateCSRFToken();

    // Set the token cookie
    res.cookie(defaultOptions.cookieName, token, defaultOptions.cookie);

    // Store token in request for use in templates
    (req as any).csrfToken = token;

    logger.debug(`[${correlationId}] CSRF token provided`, {
      path: req.path,
      method: req.method,
      correlationId,
    });

    next();
  } catch (error) {
    logger.error('CSRF token provider middleware error', {
      error,
      correlationId: getCurrentCorrelationId(),
    });
    next();
  }
};

/**
 * Get CSRF token from request
 * @param req Express request
 * @returns CSRF token
 */
export function getCSRFToken(req: Request): string {
  return (req as any).csrfToken || '';
}
