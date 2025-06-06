import type { Request, Response, NextFunction } from 'express';
import { logger } from '../../infrastructure/logging/logger';
import { getCurrentCorrelationId } from './correlation-id.middleware';
import { env } from '../../config/environment';

/**
 * Request logger options
 */
interface RequestLoggerOptions {
  // Whether to log request body
  logBody: boolean;
  // Whether to log request headers
  logHeaders: boolean;
  // Whether to log response body
  logResponseBody: boolean;
  // Whether to log response time
  logResponseTime: boolean;
  // Whether to log user information
  logUserInfo: boolean;
  // Whether to log device information
  logDeviceInfo: boolean;
  // Headers to exclude from logging
  excludeHeaders: string[];
  // Paths to exclude from logging
  excludePaths: string[];
  // Methods to exclude from logging
  excludeMethods: string[];
  // Whether to log in production
  logInProduction: boolean;
}

/**
 * Log data interface
 */
interface LogData {
  correlationId: string;
  ip: string;
  method: string;
  url: string;
  userAgent?: string;
  user?: {
    id: string;
    email: string;
  };
  deviceId?: string;
  headers?: Record<string, any>;
  body?: Record<string, any>;
  statusCode?: number;
  duration?: number;
  contentLength?: number | string;
  [key: string]: any; // Allow additional properties
}

/**
 * Default request logger options
 */
const defaultOptions: RequestLoggerOptions = {
  logBody: !env.isProduction(),
  logHeaders: !env.isProduction(),
  logResponseBody: false, // Response body logging is expensive
  logResponseTime: true,
  logUserInfo: true,
  logDeviceInfo: true,
  excludeHeaders: [
    'authorization',
    'cookie',
    'set-cookie',
    'x-auth-token',
    'x-refresh-token',
    'password',
    'secret',
    'token',
  ],
  excludePaths: ['/health', '/metrics', '/favicon.ico'],
  excludeMethods: [],
  logInProduction: true,
};

/**
 * Process content length from response header
 * @param value Content length value from response header
 * @returns Processed content length as number or string
 */
function processContentLength(value: string | number | string[] | undefined): number | string {
  if (Array.isArray(value)) {
    // If it's an array, take the first value or return 0
    // Using nullish coalescing to ensure we always return a string or number
    return value[0] ?? 0;
  }
  // Otherwise return the value or 0
  return value ?? 0;
}

/**
 * Sanitize object for logging
 * @param obj Object to sanitize
 * @param keysToExclude Keys to exclude
 * @returns Sanitized object
 */
function sanitizeForLogging(
  obj: Record<string, any>,
  keysToExclude: string[]
): Record<string, any> {
  if (!obj || typeof obj !== 'object') {
    return obj;
  }

  const sanitized: Record<string, any> = {};

  for (const [key, value] of Object.entries(obj)) {
    // Skip excluded keys
    if (keysToExclude.some(excludeKey => key.toLowerCase().includes(excludeKey.toLowerCase()))) {
      sanitized[key] = '[REDACTED]';
      continue;
    }

    // Recursively sanitize nested objects
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      sanitized[key] = sanitizeForLogging(value, keysToExclude);
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

/**
 * Create request logger middleware with custom options
 * @param options Request logger options
 * @returns Request logger middleware
 */
export function createRequestLoggerMiddleware(options: Partial<RequestLoggerOptions> = {}) {
  // Merge options with defaults
  const mergedOptions: RequestLoggerOptions = { ...defaultOptions, ...options };

  return (req: Request, res: Response, next: NextFunction): void => {
    // Skip logging for excluded paths
    if (mergedOptions.excludePaths.some(path => req.path.startsWith(path))) {
      return next();
    }

    // Skip logging for excluded methods
    if (mergedOptions.excludeMethods.includes(req.method)) {
      return next();
    }

    // Skip logging in production if disabled
    if (env.isProduction() && !mergedOptions.logInProduction) {
      return next();
    }

    try {
      // Get request information
      const startTime = Date.now();
      const method = req.method;
      const url = req.originalUrl || req.url;
      const ip = req.ip || req.socket.remoteAddress || 'unknown';
      const userAgent = req.headers['user-agent'] || 'unknown';
      const correlationId =
        getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

      // Prepare log data
      const logData: LogData = {
        correlationId,
        ip,
        method,
        url,
      };

      // Add user agent
      logData.userAgent = userAgent;

      // Add user information if available and enabled
      if (mergedOptions.logUserInfo && req.user) {
        logData.user = {
          id: req.user.id,
          email: req.user.email,
        };
      }

      // Add device information if available and enabled
      if (mergedOptions.logDeviceInfo && req.deviceId) {
        logData.deviceId = req.deviceId;
      }

      // Add headers if enabled
      if (mergedOptions.logHeaders) {
        logData.headers = sanitizeForLogging(req.headers, mergedOptions.excludeHeaders);
      }

      // Add body if enabled
      if (mergedOptions.logBody && req.body) {
        logData.body = sanitizeForLogging(req.body, mergedOptions.excludeHeaders);
      }

      // Log request
      logger.info(`${method} ${url}`, logData);

      // Add response listener to log response
      res.on('finish', () => {
        // Calculate request duration
        const duration = Date.now() - startTime;

        // Get response information
        const statusCode = res.statusCode;
        const contentLength = processContentLength(res.getHeader('content-length'));

        // Prepare response log data
        const responseLogData: LogData = {
          correlationId,
          ip,
          method,
          url,
          statusCode,
          duration,
          contentLength,
        };

        // Add response body if enabled
        if (mergedOptions.logResponseBody && (res as any).body) {
          responseLogData.body = sanitizeForLogging(
            (res as any).body,
            mergedOptions.excludeHeaders
          );
        }

        // Log response based on status code
        if (statusCode >= 500) {
          logger.error(`${method} ${url} ${statusCode} - ${duration}ms`, responseLogData);
        } else if (statusCode >= 400) {
          logger.warn(`${method} ${url} ${statusCode} - ${duration}ms`, responseLogData);
        } else {
          logger.info(`${method} ${url} ${statusCode} - ${duration}ms`, responseLogData);
        }
      });

      next();
    } catch (error) {
      logger.error('Request logger middleware error', {
        error,
        correlationId: getCurrentCorrelationId(),
      });
      next();
    }
  };
}

/**
 * Default request logger middleware
 */
export const requestLogger = createRequestLoggerMiddleware();

/**
 * Minimal request logger middleware
 * Only logs essential information
 */
export const minimalRequestLogger = createRequestLoggerMiddleware({
  logBody: false,
  logHeaders: false,
  logResponseBody: false,
  logUserInfo: false,
  logDeviceInfo: false,
});

/**
 * Detailed request logger middleware
 * Logs all available information
 */
export const detailedRequestLogger = createRequestLoggerMiddleware({
  logBody: true,
  logHeaders: true,
  logResponseBody: true,
  logUserInfo: true,
  logDeviceInfo: true,
});

/**
 * API request logger middleware
 * Logs information relevant for API requests
 */
export const apiRequestLogger = createRequestLoggerMiddleware({
  logBody: !env.isProduction(),
  logHeaders: false,
  logResponseBody: false,
  logUserInfo: true,
  logDeviceInfo: true,
});
