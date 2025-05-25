import type { Request, Response, NextFunction } from 'express';
import 'express-session';
import { randomBytes } from 'crypto';
import { securityConfig } from '../../../config/security-config';
import { logger } from '../../logging/logger';
import { encryption } from '../crypto/encryption';
import { AuthorizationError } from '../../../utils/error-handling';

/**
 * CSRF Protection service
 * Provides CSRF token generation and validation
 */
export class CsrfProtection {
  /**
   * Generate a CSRF token
   * @param req Express request
   * @param res Express response
   * @returns CSRF token
   */
  public static generateToken(req: Request, res: Response): string {
    // Skip if CSRF protection is disabled
    if (!securityConfig.csrf.enabled) {
      return '';
    }

    try {
      // Generate a random token
      const token = randomBytes(32).toString('hex');

      // Create a signed token with user session ID (if available) and timestamp
      const sessionId = (req as any).session?.id || 'anonymous';
      const timestamp = Date.now();
      const payload = `${sessionId}:${timestamp}:${token}`;

      // Sign the token with HMAC
      const signedToken = encryption.hmacSign(
        payload,
        securityConfig.csrf.secret || securityConfig.jwt.accessTokenSecret
      );

      // Set the token in a cookie
      res.cookie(securityConfig.csrf.cookieName, signedToken, {
        httpOnly: true,
        secure: process.env['NODE_ENV'] === 'production',
        sameSite: 'strict',
        path: '/',
      });

      return token;
    } catch (error) {
      logger.error('Failed to generate CSRF token', { error });
      return '';
    }
  }

  /**
   * Validate a CSRF token
   * @param req Express request
   * @returns True if the token is valid, false otherwise
   */
  public static validateToken(req: Request): boolean {
    // Skip if CSRF protection is disabled
    if (!securityConfig.csrf.enabled) {
      return true;
    }

    try {
      // Get the token from the request header
      const token = req.headers[securityConfig.csrf.headerName.toLowerCase()] as string;

      // Get the signed token from the cookie
      const signedToken = req.cookies?.[securityConfig.csrf.cookieName];

      // If either token is missing, validation fails
      if (!token || !signedToken) {
        return false;
      }

      // Extract the payload from the signed token
      const [sessionId, timestamp, originalToken] = signedToken.split(':');

      // Validate the token
      const payload = `${sessionId}:${timestamp}:${originalToken}`;
      const isValid = signedToken
        ? encryption.hmacVerify(
            payload,
            signedToken,
            securityConfig.csrf.secret || securityConfig.jwt.accessTokenSecret
          )
        : false;

      // Check if the token matches the one in the header
      const tokensMatch = originalToken === token;

      // Check if the token has expired (optional, based on your security requirements)
      const tokenAge = Date.now() - parseInt(timestamp, 10);
      const maxAge = 24 * 60 * 60 * 1000; // 24 hours
      const isExpired = tokenAge > maxAge;

      return isValid && tokensMatch && !isExpired;
    } catch (error) {
      logger.error('Failed to validate CSRF token', { error });
      return false;
    }
  }

  /**
   * CSRF protection middleware
   * @param options Middleware options
   * @returns Express middleware function
   */
  public static middleware(
    options: {
      ignoreMethods?: string[];
      ignorePaths?: string[];
      message?: string;
    } = {}
  ) {
    const {
      ignoreMethods = ['GET', 'HEAD', 'OPTIONS'],
      ignorePaths = [],
      message = 'Invalid CSRF token',
    } = options;

    return (_req: Request, _res: Response, next: NextFunction) => {
      // Skip if CSRF protection is disabled
      if (!securityConfig.csrf.enabled) {
        return next();
      }

      // Skip for ignored methods
      if (ignoreMethods.includes(_req.method)) {
        return next();
      }

      // Skip for ignored paths
      if (ignorePaths.some(path => _req.path.startsWith(path))) {
        return next();
      }

      // Validate the token
      if (!this.validateToken(_req)) {
        logger.warn('CSRF token validation failed', {
          ip: _req.ip,
          path: _req.path,
          method: _req.method,
        });
        return next(new AuthorizationError(message, 'INVALID_CSRF_TOKEN'));
      }

      next();
    };
  }

  /**
   * Generate a CSRF token and add it to the response locals
   * This middleware should be used before rendering templates
   * @returns Express middleware function
   */
  public static tokenMiddleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      // Skip if CSRF protection is disabled
      if (!securityConfig.csrf.enabled) {
        return next();
      }

      // Generate a token
      const token = this.generateToken(req, res);

      // Add the token to the response locals
      res.locals['csrfToken'] = token;

      next();
    };
  }
}

// Export middleware functions
export const csrfProtect = CsrfProtection.middleware();
export const csrfToken = CsrfProtection.tokenMiddleware();
