import type { Response } from 'express';
import { AppError } from '../../utils/error-handling';
import { logger } from '../../infrastructure/logging/logger';
import { getCurrentCorrelationId } from '../middlewares/correlation-id.middleware';

/**
 * Send an error response
 * @param res Express response object
 * @param error Error object
 * @param statusCode HTTP status code
 */
export function sendErrorResponse(res: Response, error: Error | AppError, statusCode = 500): void {
  const correlationId = getCurrentCorrelationId() || 'unknown';

  // Default error response
  const errorResponse = {
    status: 'error',
    message: error.message || 'Internal server error',
    code: (error as AppError).code || 'INTERNAL_ERROR',
    correlationId,
    timestamp: new Date().toISOString(),
  };

  // Log error
  logger.error(`[${correlationId}] ${error.message || 'Internal server error'}`, {
    error,
    correlationId,
    stack: error.stack,
  });

  // Send response
  res.status(statusCode).json(errorResponse);
}

/**
 * Send a bad request error response
 * @param res Express response object
 * @param message Error message
 * @param code Error code
 */
export function sendBadRequestResponse(
  res: Response,
  message = 'Bad request',
  code = 'BAD_REQUEST'
): void {
  const correlationId = getCurrentCorrelationId() || 'unknown';

  res.status(400).json({
    status: 'error',
    message,
    code,
    correlationId,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Send an unauthorized error response
 * @param res Express response object
 * @param message Error message
 * @param code Error code
 */
export function sendUnauthorizedResponse(
  res: Response,
  message = 'Unauthorized',
  code = 'UNAUTHORIZED'
): void {
  const correlationId = getCurrentCorrelationId() || 'unknown';

  res.status(401).json({
    status: 'error',
    message,
    code,
    correlationId,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Send a forbidden error response
 * @param res Express response object
 * @param message Error message
 * @param code Error code
 */
export function sendForbiddenResponse(
  res: Response,
  message = 'Forbidden',
  code = 'FORBIDDEN'
): void {
  const correlationId = getCurrentCorrelationId() || 'unknown';

  res.status(403).json({
    status: 'error',
    message,
    code,
    correlationId,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Send a not found error response
 * @param res Express response object
 * @param message Error message
 * @param code Error code
 */
export function sendNotFoundResponse(
  res: Response,
  message = 'Resource not found',
  code = 'NOT_FOUND'
): void {
  const correlationId = getCurrentCorrelationId() || 'unknown';

  res.status(404).json({
    status: 'error',
    message,
    code,
    correlationId,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Send a conflict error response
 * @param res Express response object
 * @param message Error message
 * @param code Error code
 */
export function sendConflictResponse(
  res: Response,
  message = 'Resource conflict',
  code = 'CONFLICT'
): void {
  const correlationId = getCurrentCorrelationId() || 'unknown';

  res.status(409).json({
    status: 'error',
    message,
    code,
    correlationId,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Send a too many requests error response
 * @param res Express response object
 * @param message Error message
 * @param code Error code
 * @param retryAfter Seconds to wait before retrying
 */
export function sendTooManyRequestsResponse(
  res: Response,
  message = 'Too many requests',
  code = 'TOO_MANY_REQUESTS',
  retryAfter = 60
): void {
  const correlationId = getCurrentCorrelationId() || 'unknown';

  res.setHeader('Retry-After', retryAfter.toString());

  res.status(429).json({
    status: 'error',
    message,
    code,
    correlationId,
    retryAfter,
    timestamp: new Date().toISOString(),
  });
}
