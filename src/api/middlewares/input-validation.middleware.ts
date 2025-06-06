import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { ValidationError } from '../../utils/error-handling';
import { logger } from '../../infrastructure/logging/logger';
import { getCurrentCorrelationId } from './correlation-id.middleware';

/**
 * Validation options interface
 */
interface ValidationOptions {
  source?: 'body' | 'query' | 'params' | 'headers';
  stripUnknown?: boolean;
  abortEarly?: boolean;
  errorCode?: string;
  errorMessage?: string;
}

/**
 * Default validation options
 */
const defaultOptions: ValidationOptions = {
  source: 'body',
  stripUnknown: true,
  abortEarly: false,
  errorCode: 'VALIDATION_ERROR',
  errorMessage: 'Validation failed',
};

/**
 * Format Zod errors into a more user-friendly format
 * @param error Zod error
 * @returns Formatted errors
 */
function formatZodErrors(error: z.ZodError): Record<string, string[]> {
  const errors: Record<string, string[]> = {};

  for (const issue of error.errors) {
    const path = issue.path.join('.') || '_general';

    if (!errors[path]) {
      errors[path] = [];
    }

    errors[path].push(issue.message);
  }

  return errors;
}

/**
 * Safely set a property on a request object
 * @param req Request object
 * @param source Source property
 * @param data Data to set
 */
function safelySetRequestProperty(req: Request, source: string, data: unknown): void {
  // Handle each source type specifically to avoid read-only property errors
  if (source === 'body') {
    req.body = data as any;
  } else if (source === 'query') {
    // For query, we need to merge with existing query params
    // since some may be added by Express and are read-only
    Object.keys(req.query).forEach(key => {
      if (!(data as Record<string, any>)[key]) {
        (data as Record<string, any>)[key] = req.query[key];
      }
    });

    // Then assign validated properties back to query
    Object.keys(data as Record<string, any>).forEach(key => {
      req.query[key] = (data as Record<string, any>)[key];
    });
  } else if (source === 'params') {
    // For params, we need to merge with existing params
    // since some may be added by Express and are read-only
    Object.keys(req.params).forEach(key => {
      if (!(data as Record<string, any>)[key]) {
        (data as Record<string, any>)[key] = req.params[key];
      }
    });

    // Then assign validated properties back to params
    Object.keys(data as Record<string, any>).forEach(key => {
      req.params[key] = (data as Record<string, any>)[key];
    });
  } else if (source === 'headers') {
    // Headers are read-only, so we can only log validation
    logger.debug('Headers validated but not modified (read-only)');
  }
}

/**
 * Middleware factory for validating request data against a Zod schema
 * @param schema Zod schema to validate against
 * @param options Validation options
 * @returns Middleware function
 */
export const validate = (schema: z.ZodType, options: ValidationOptions = {}) => {
  // Merge options with defaults
  const mergedOptions = { ...defaultOptions, ...options };
  const { source, errorCode, errorMessage } = mergedOptions;

  return (req: Request, _res: Response, next: NextFunction) => {
    try {
      const correlationId =
        getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

      // Get data from the specified source
      const data = req[source as keyof Request];

      if (!data) {
        logger.warn(`[${correlationId}] Validation source '${source}' is empty or undefined`, {
          path: req.path,
          method: req.method,
          source,
        });

        // If source is empty, pass validation if schema allows undefined/null
        try {
          schema.parse(undefined);
          return next();
        } catch (error) {
          // Source is required but missing
          throw new ValidationError(
            `${errorMessage}: ${source} is required`,
            { _general: [`${source} is required`] },
            errorCode
          );
        }
      }

      // Validate data against schema
      const validatedData = schema.parse(data);

      // Safely set the validated data back to the request
      safelySetRequestProperty(req, source as string, validatedData);

      next();
    } catch (error) {
      const correlationId =
        getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

      if (error instanceof z.ZodError) {
        // Format Zod errors
        const formattedErrors = formatZodErrors(error);

        logger.warn(`[${correlationId}] Validation error`, {
          errors: formattedErrors,
          path: req.path,
          method: req.method,
          source,
        });

        // Create a ValidationError with formatted errors
        next(new ValidationError(errorMessage as string, formattedErrors, errorCode));
      } else {
        // Pass through other errors
        logger.error(`[${correlationId}] Unexpected validation error`, {
          error,
          path: req.path,
          method: req.method,
          source,
        });

        next(error);
      }
    }
  };
};

/**
 * Validate body middleware
 * @param schema Zod schema to validate against
 * @param options Validation options
 * @returns Middleware function
 */
export const validateBody = (
  schema: z.ZodType,
  options: Omit<ValidationOptions, 'source'> = {}
) => {
  return validate(schema, { ...options, source: 'body' });
};

/**
 * Validate query middleware
 * @param schema Zod schema to validate against
 * @param options Validation options
 * @returns Middleware function
 */
export const validateQuery = (
  schema: z.ZodType,
  options: Omit<ValidationOptions, 'source'> = {}
) => {
  return validate(schema, { ...options, source: 'query' });
};

/**
 * Validate params middleware
 * @param schema Zod schema to validate against
 * @param options Validation options
 * @returns Middleware function
 */
export const validateParams = (
  schema: z.ZodType,
  options: Omit<ValidationOptions, 'source'> = {}
) => {
  return validate(schema, { ...options, source: 'params' });
};

/**
 * Validate headers middleware
 * @param schema Zod schema to validate against
 * @param options Validation options
 * @returns Middleware function
 */
export const validateHeaders = (
  schema: z.ZodType,
  options: Omit<ValidationOptions, 'source'> = {}
) => {
  return validate(schema, { ...options, source: 'headers' });
};

/**
 * Validate request middleware
 * Validates multiple parts of the request at once
 * @param schemas Object containing schemas for different parts of the request
 * @param options Validation options
 * @returns Middleware function
 */
export const validateRequest = (
  schemas: {
    body?: z.ZodType;
    query?: z.ZodType;
    params?: z.ZodType;
    headers?: z.ZodType;
  },
  options: Omit<ValidationOptions, 'source'> = {}
) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    // Create an array of middleware functions
    const middlewares: Array<(req: Request, res: Response, next: (err?: any) => void) => void> = [];

    if (schemas.body) {
      middlewares.push(validateBody(schemas.body, options));
    }

    if (schemas.query) {
      middlewares.push(validateQuery(schemas.query, options));
    }

    if (schemas.params) {
      middlewares.push(validateParams(schemas.params, options));
    }

    if (schemas.headers) {
      middlewares.push(validateHeaders(schemas.headers, options));
    }

    // Execute middlewares in sequence
    const executeMiddleware = (index: number) => {
      if (index >= middlewares.length) {
        return next();
      }

      const middleware = middlewares[index];
      if (!middleware) {
        return next();
      }

      middleware(req, _res, (err?: any) => {
        if (err) {
          return next(err);
        }
        executeMiddleware(index + 1);
      });
    };

    executeMiddleware(0);
  };
};
