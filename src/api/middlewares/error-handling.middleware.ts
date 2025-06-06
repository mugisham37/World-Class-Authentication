import type { Request, Response, NextFunction } from 'express';
import {
  AppError,
  ValidationError,
  AuthenticationError,
  RateLimitError,
  TooManyRequestsError,
  NotFoundError,
  getErrorDetails,
} from '../../utils/error-handling';
import { logger } from '../../infrastructure/logging/logger';
import { env } from '../../config/environment';
import { getCurrentCorrelationId } from './correlation-id.middleware';

/**
 * Global error handling middleware
 * Catches all errors and formats appropriate responses
 */
export const errorHandler = (
  err: Error,
  req: Request,
  res: Response,
  _next: NextFunction
): void => {
  // Get correlation ID for request tracing
  const correlationId =
    getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

  // Default error response
  const errorResponse = {
    status: 'error',
    message: 'Internal server error',
    code: 'INTERNAL_ERROR',
    correlationId,
  };

  // Handle known error types
  if (err instanceof AppError) {
    // This is a known operational error
    const statusCode = getStatusCodeForError(err);

    errorResponse.message = err.message;
    errorResponse.code = err.code;

    // Include error details in non-production environments
    if (!env.isProduction() && err instanceof ValidationError) {
      (errorResponse as any).errors = err.errors;
    }

    // Log based on severity
    if (statusCode >= 500) {
      logger.error(`[${correlationId}] ${err.message}`, {
        error: err,
        path: req.path,
        method: req.method,
        ip: req.ip,
        correlationId,
      });
    } else {
      logger.warn(`[${correlationId}] ${err.message}`, {
        error: err,
        path: req.path,
        method: req.method,
        ip: req.ip,
        correlationId,
      });
    }

    res.status(statusCode).json(errorResponse);
  } else if (err instanceof ValidationError) {
    // Handle validation errors
    errorResponse.message = 'Validation error';
    errorResponse.code = 'VALIDATION_ERROR';
    (errorResponse as any).errors = err.errors;

    logger.warn(`[${correlationId}] Validation error`, {
      errors: err.errors,
      path: req.path,
      method: req.method,
      correlationId,
    });

    res.status(400).json(errorResponse);
  } else {
    // Unknown error - could be a programming error
    const errorDetails = getErrorDetails(err);

    logger.error(`[${correlationId}] Unhandled error: ${errorDetails.message}`, {
      error: err,
      stack: errorDetails.stack,
      path: req.path,
      method: req.method,
      ip: req.ip,
      correlationId,
    });

    // In non-production environments, include error details
    if (!env.isProduction()) {
      errorResponse.message = errorDetails.message;
      (errorResponse as any).stack = errorDetails.stack;
    }

    res.status(500).json(errorResponse);
  }
};

/**
 * Get HTTP status code for an error
 * @param err Error to get status code for
 * @returns HTTP status code
 */
function getStatusCodeForError(err: AppError): number {
  // Default status code
  let statusCode = 500;

  // Determine status code based on error type
  if (err instanceof AuthenticationError) {
    statusCode = 401;
  } else if (err instanceof RateLimitError || err instanceof TooManyRequestsError) {
    statusCode = 429;
  } else if (err instanceof ValidationError) {
    statusCode = 400;
  } else if (err instanceof NotFoundError) {
    statusCode = 404;
  } else if (err.code) {
    // Map error codes to status codes
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
        statusCode = 400;
        break;
      case 'UNAUTHORIZED':
      case 'AUTHENTICATION_ERROR':
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

/**
 * Not found middleware
 * Handles requests to non-existent routes
 */
export const notFoundHandler = (req: Request, res: Response): void => {
  const correlationId =
    getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

  logger.warn(`[${correlationId}] Route not found: ${req.method} ${req.path}`, {
    path: req.path,
    method: req.method,
    ip: req.ip,
    correlationId,
  });

  res.status(404).json({
    status: 'error',
    message: 'Route not found',
    code: 'NOT_FOUND',
    correlationId,
  });
};

/**
 * Method not allowed middleware
 * Handles requests with unsupported HTTP methods
 */
export const methodNotAllowedHandler = (req: Request, res: Response): void => {
  const correlationId =
    getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

  logger.warn(`[${correlationId}] Method not allowed: ${req.method} ${req.path}`, {
    path: req.path,
    method: req.method,
    ip: req.ip,
    correlationId,
  });

  res.status(405).json({
    status: 'error',
    message: 'Method not allowed',
    code: 'METHOD_NOT_ALLOWED',
    correlationId,
  });
};
