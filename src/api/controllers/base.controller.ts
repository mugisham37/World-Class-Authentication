import type { Request, Response, NextFunction } from 'express';
import { AuthUser } from './types/auth.types';

/**
 * Extended request interface with properly typed user property
 */
export interface ExtendedRequest extends Request {
  user?: AuthUser;
}
import { logger } from '../../infrastructure/logging/logger';
import { getCurrentCorrelationId } from '../middlewares/correlation-id.middleware';
import { AppError } from '../../utils/error-handling';
import { sendErrorResponse } from '../responses/error.responses';

/**
 * Base controller class
 * Provides common functionality for all controllers
 */
export abstract class BaseController {
  /**
   * Handle async request with error handling
   * @param handler Request handler function
   * @returns Express middleware function
   */
  protected handleAsync = (
    handler: (req: ExtendedRequest, res: Response, next: NextFunction) => Promise<void>
  ) => {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const correlationId = getCurrentCorrelationId() || 'unknown';

        // Use explicit type assertion for req.user to ensure TypeScript recognizes the id property
        const typedUser = req.user as AuthUser | undefined;

        logger.debug(`[${correlationId}] Processing request: ${req.method} ${req.path}`, {
          correlationId,
          userId: typedUser?.id,
          path: req.path,
          method: req.method,
        });

        await handler(req as ExtendedRequest, res, next);
      } catch (error) {
        this.handleError(error, req as ExtendedRequest, res, next);
      }
    };
  };

  /**
   * Handle error
   * @param error Error object
   * @param req Express request
   * @param res Express response
   * @param next Express next function
   */
  protected handleError = (
    error: unknown,
    req: ExtendedRequest,
    res: Response,
    next: NextFunction
  ): void => {
    const correlationId = getCurrentCorrelationId() || 'unknown';

    // If headers already sent, pass to next error handler
    if (res.headersSent) {
      return next(error);
    }

    // Handle AppError
    if (error instanceof AppError) {
      const statusCode = this.getStatusCodeForError(error);
      sendErrorResponse(res, error, statusCode);
      return;
    }

    // Handle other errors
    const appError = new AppError(
      (error as Error)?.message || 'Internal server error',
      'INTERNAL_ERROR'
    );

    logger.error(`[${correlationId}] Unhandled error in controller`, {
      error,
      path: req.path,
      method: req.method,
      correlationId,
      stack: (error as Error)?.stack,
    });

    sendErrorResponse(res, appError, 500);
  };

  /**
   * Get HTTP status code for an error
   * @param err Error to get status code for
   * @returns HTTP status code
   */
  private getStatusCodeForError(err: AppError): number {
    // Default status code
    let statusCode = 500;

    // Determine status code based on error code
    if (err.code) {
      switch (err.code) {
        case 'NOT_FOUND':
        case 'RESOURCE_NOT_FOUND':
          statusCode = 404;
          break;
        case 'FORBIDDEN':
        case 'AUTHORIZATION_ERROR':
          statusCode = 403;
          break;
        case 'BAD_REQUEST':
        case 'VALIDATION_ERROR':
          statusCode = 400;
          break;
        case 'UNAUTHORIZED':
        case 'AUTHENTICATION_ERROR':
        case 'NOT_AUTHENTICATED':
          statusCode = 401;
          break;
        case 'CONFLICT':
        case 'CONFLICT_ERROR':
          statusCode = 409;
          break;
        case 'UNPROCESSABLE_ENTITY':
          statusCode = 422;
          break;
        case 'TOO_MANY_REQUESTS':
        case 'RATE_LIMIT_ERROR':
          statusCode = 429;
          break;
        case 'SERVICE_UNAVAILABLE':
          statusCode = 503;
          break;
      }
    }

    return statusCode;
  }
}
