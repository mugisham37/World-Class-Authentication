import type { Request, Response, NextFunction } from 'express';
import { authService } from '../../core/authentication/auth.service';
import { AppError } from '../../utils/error-handling';
import { logger } from '../../infrastructure/logging/logger';
import { getCurrentCorrelationId } from './correlation-id.middleware';

/**
 * Authentication error class
 */
export class AuthenticationError extends AppError {
  constructor(message: string, code: string = 'AUTHENTICATION_ERROR') {
    super(message, code);
  }
}

/**
 * Authentication middleware
 * Verifies the JWT token and adds user info to the request
 */
export const authenticate = async (
  req: Request,
  _res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const correlationId =
      getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

    // Get authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      throw new AuthenticationError('No authorization header provided', 'NO_AUTH_HEADER');
    }

    // Check if it's a Bearer token
    if (!authHeader.startsWith('Bearer ')) {
      throw new AuthenticationError('Invalid authorization header format', 'INVALID_AUTH_HEADER');
    }

    // Extract token
    const token = authHeader.substring(7);

    // Validate token
    const { userId, email, sessionId } = await authService.validateAccessToken(token);

    // Add user info to request
    req.user = {
      id: userId,
      email,
      sessionId,
    };

    // Log successful authentication
    logger.debug(`[${correlationId}] User authenticated`, {
      userId,
      email,
      sessionId,
      correlationId,
    });

    next();
  } catch (error) {
    if (error instanceof AuthenticationError) {
      next(error);
    } else {
      logger.error('Authentication middleware error', {
        error,
        correlationId: getCurrentCorrelationId(),
      });
      next(new AuthenticationError('Authentication failed', 'AUTH_FAILED'));
    }
  }
};

/**
 * Optional authentication middleware
 * Tries to authenticate the user but doesn't fail if no token is provided
 */
export const optionalAuthenticate = async (
  req: Request,
  _res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const correlationId =
      getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

    // Get authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      // No token provided, continue without authentication
      return next();
    }

    // Check if it's a Bearer token
    if (!authHeader.startsWith('Bearer ')) {
      // Invalid format, continue without authentication
      return next();
    }

    // Extract token
    const token = authHeader.substring(7);

    try {
      // Validate token
      const { userId, email, sessionId } = await authService.validateAccessToken(token);

      // Add user info to request
      req.user = {
        id: userId,
        email,
        sessionId,
      };

      // Log successful authentication
      logger.debug(`[${correlationId}] User optionally authenticated`, {
        userId,
        email,
        sessionId,
        correlationId,
      });
    } catch (tokenError) {
      // Token validation failed, continue without authentication
      logger.debug(`[${correlationId}] Optional authentication failed`, {
        error: tokenError,
        correlationId,
      });
    }

    next();
  } catch (error) {
    // Continue without authentication on error
    logger.error('Optional authentication middleware error', {
      error,
      correlationId: getCurrentCorrelationId(),
    });
    next();
  }
};

// Note: Express Request interface extensions are now centralized in src/shared/types/express.d.ts
