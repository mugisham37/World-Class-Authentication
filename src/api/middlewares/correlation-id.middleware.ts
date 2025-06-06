import type { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { AsyncLocalStorage } from 'async_hooks';

// Create AsyncLocalStorage to store correlation ID for the current request
const correlationIdStorage = new AsyncLocalStorage<string>();

/**
 * Get the current correlation ID from AsyncLocalStorage
 * @returns The current correlation ID or undefined if not set
 */
export function getCurrentCorrelationId(): string | undefined {
  return correlationIdStorage.getStore();
}

/**
 * Middleware to add a correlation ID to each request
 * This helps with request tracing across the application
 */
export const correlationIdMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  // Use existing correlation ID from header or generate a new one
  const correlationId = (req.headers['x-correlation-id'] as string) || uuidv4();

  // Add correlation ID to request headers
  req.headers['x-correlation-id'] = correlationId;

  // Add correlation ID to response headers
  res.setHeader('x-correlation-id', correlationId);

  // Store correlation ID in AsyncLocalStorage for the current request
  correlationIdStorage.run(correlationId, () => {
    next();
  });
};
