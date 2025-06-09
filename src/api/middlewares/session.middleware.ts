import type { Request, Response, NextFunction } from 'express';
import { sessionService } from '../../core/authentication/session.service';
import { logger } from '../../infrastructure/logging/logger';
import { getCurrentCorrelationId } from './correlation-id.middleware';
import { AppError } from '../../utils/error-handling';

/**
 * Session error class
 */
export class SessionError extends AppError {
  constructor(message: string, code: string = 'SESSION_ERROR') {
    super(message, code);
  }
}

/**
 * Middleware to update session activity
 * Updates the last active time for the current session
 */
export const updateSessionActivity = async (
  req: Request,
  _res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const correlationId =
      getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

    // Check if user is authenticated and has a session
    if (req.user?.sessionId) {
      // Update session activity in the background
      // Don't await to avoid blocking the request
      sessionService.updateSessionActivity(req.user.sessionId).catch(error => {
        logger.error(`[${correlationId}] Failed to update session activity`, {
          error,
          sessionId: req.user?.sessionId,
          userId: req.user?.id,
          correlationId,
        });
      });
    }

    next();
  } catch (error) {
    // Don't block the request if session update fails
    logger.error('Session activity middleware error', {
      error,
      correlationId: getCurrentCorrelationId(),
    });
    next();
  }
};

/**
 * Middleware to check session expiration
 * Checks if the current session has expired
 */
export const checkSessionExpiration = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const correlationId =
      getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

    // Check if user is authenticated and has a session
    if (req.user?.sessionId) {
      // Get session
      const session = await sessionService.getSessionById(req.user.sessionId);

      // Check if session exists and is not expired
      if (!session || session.expiresAt < new Date()) {
        // Log session expiration
        logger.warn(`[${correlationId}] Session expired`, {
          sessionId: req.user.sessionId,
          userId: req.user.id,
          correlationId,
        });

        // Clear user from request
        delete req.user;

        // Clear refresh token cookie
        res.clearCookie('refreshToken', {
          httpOnly: true,
          secure: process.env['NODE_ENV'] === 'production',
          sameSite: 'strict',
          path: '/',
        });

        // Return unauthorized response
        return next(new SessionError('Session expired', 'SESSION_EXPIRED'));
      }
    }

    next();
  } catch (error) {
    logger.error('Session expiration middleware error', {
      error,
      correlationId: getCurrentCorrelationId(),
    });
    next(new SessionError('Session validation failed', 'SESSION_VALIDATION_FAILED'));
  }
};

/**
 * Middleware to validate session
 * Checks if the session exists and is valid
 */
export const validateSession = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const correlationId =
      getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

    // Check if user is authenticated and has a session
    if (!req.user?.sessionId) {
      return next();
    }

    // Get session
    const session = await sessionService.getSessionById(req.user.sessionId);

    // Check if session exists
    if (!session) {
      // Log session not found
      logger.warn(`[${correlationId}] Session not found`, {
        sessionId: req.user.sessionId,
        userId: req.user.id,
        correlationId,
      });

      // Clear user from request
      delete req.user;

      // Clear refresh token cookie
      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env['NODE_ENV'] === 'production',
        sameSite: 'strict',
        path: '/',
      });

      // Return unauthorized response
      return next(new SessionError('Session not found', 'SESSION_NOT_FOUND'));
    }

    // Check if session is active
    if (!session.isActive) {
      // Log inactive session
      logger.warn(`[${correlationId}] Session inactive`, {
        sessionId: req.user.sessionId,
        userId: req.user.id,
        correlationId,
      });

      // Clear user from request
      delete req.user;

      // Clear refresh token cookie
      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env['NODE_ENV'] === 'production',
        sameSite: 'strict',
        path: '/',
      });

      // Return unauthorized response
      return next(new SessionError('Session inactive', 'SESSION_INACTIVE'));
    }

    // Add session to request
    req.customSession = session;

    next();
  } catch (error) {
    logger.error('Session validation middleware error', {
      error,
      correlationId: getCurrentCorrelationId(),
    });
    next(new SessionError('Session validation failed', 'SESSION_VALIDATION_FAILED'));
  }
};

/**
 * Middleware to check session device
 * Verifies that the request is coming from the same device that created the session
 */
export const checkSessionDevice = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const correlationId =
      getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

    // Check if user is authenticated and has a session
    if (!req.user?.sessionId || !req.customSession) {
      return next();
    }

    // Get session
    const session = req.customSession;

    // Check if session has a device ID
    if (!session.deviceId) {
      return next();
    }

    // Check if request has a device ID
    if (!req.deviceId) {
      // Log missing device ID
      logger.warn(`[${correlationId}] Missing device ID for session check`, {
        sessionId: req.user.sessionId,
        userId: req.user.id,
        correlationId,
      });

      return next();
    }

    // Check if device IDs match
    if (session.deviceId !== req.deviceId) {
      // Log device mismatch
      logger.warn(`[${correlationId}] Session device mismatch`, {
        sessionId: req.user.sessionId,
        userId: req.user.id,
        sessionDeviceId: session.deviceId,
        requestDeviceId: req.deviceId,
        correlationId,
      });

      // Clear user from request
      delete req.user;

      // Clear refresh token cookie
      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env['NODE_ENV'] === 'production',
        sameSite: 'strict',
        path: '/',
      });

      // Return unauthorized response
      return next(new SessionError('Session device mismatch', 'SESSION_DEVICE_MISMATCH'));
    }

    next();
  } catch (error) {
    logger.error('Session device check middleware error', {
      error,
      correlationId: getCurrentCorrelationId(),
    });
    next(new SessionError('Session device check failed', 'SESSION_DEVICE_CHECK_FAILED'));
  }
};

// Note: Express Request interface extensions are now centralized in src/shared/types/express.d.ts
