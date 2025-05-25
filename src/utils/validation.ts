import { z } from 'zod';
import { logger } from '../infrastructure/logging/logger';

/**
 * Validation Service
 * Implements comprehensive input validation with schema-based validation
 */
class ValidationService {
  /**
   * Validate configuration against a schema
   * @param schema Zod schema
   * @param config Configuration object
   * @param options Validation options
   * @returns Validated configuration
   */
  validateConfig<T extends z.ZodType>(
    schema: T,
    config: unknown,
    options: {
      exitOnFailure?: boolean;
      logErrors?: boolean;
      errorPrefix?: string;
    } = {}
  ): z.infer<T> {
    const {
      exitOnFailure = true,
      logErrors = true,
      errorPrefix = 'Configuration validation failed',
    } = options;

    try {
      // Parse and validate the configuration
      return schema.parse(config);
    } catch (error) {
      if (error instanceof z.ZodError) {
        if (logErrors) {
          logger.error(`\n❌ ${errorPrefix}:`);

          // Format and log each validation error
          error.errors.forEach(err => {
            const path = err.path.join('.');
            logger.error(`  - ${path}: ${err.message}`);
          });

          // Provide guidance on fixing the errors
          logger.error(
            '\nPlease check your environment variables and ensure they match the expected types.'
          );

          if (exitOnFailure) {
            logger.error('The application cannot start with invalid configuration.\n');
            process.exit(1);
          }
        }

        // Transform Zod errors into a more API-friendly format
        const formattedErrors = error.errors.reduce(
          (acc, err) => {
            const path = err.path.join('.');
            acc[path] = err.message;
            return acc;
          },
          {} as Record<string, string>
        );

        // Throw a formatted error object
        throw {
          status: 400,
          code: 'VALIDATION_ERROR',
          message: errorPrefix,
          errors: formattedErrors,
        };
      }

      // Re-throw unexpected errors
      throw error;
    }
  }

  /**
   * Validate input against a schema
   * @param schema Zod schema
   * @param data Input data
   * @param options Validation options
   * @returns Validated data
   */
  validateInput<T extends z.ZodType>(
    schema: T,
    data: unknown,
    options: {
      stripUnknown?: boolean;
      errorCode?: string;
      errorMessage?: string;
    } = {}
  ): z.infer<T> {
    const {
      stripUnknown = true,
      errorCode = 'VALIDATION_ERROR',
      errorMessage = 'Validation failed',
    } = options;

    try {
      // Parse with options
      return schema.parse(data);
    } catch (error) {
      if (error instanceof z.ZodError) {
        // Transform Zod errors into a more API-friendly format
        const formattedErrors = error.errors.reduce(
          (acc, err) => {
            const path = err.path.join('.') || '_general';
            acc[path] = err.message;
            return acc;
          },
          {} as Record<string, string>
        );

        // Log validation errors in debug mode
        logger.debug('Validation error', { errors: formattedErrors, data });

        // Throw a formatted error object that can be caught by API error middleware
        throw {
          status: 400,
          code: errorCode,
          message: errorMessage,
          errors: formattedErrors,
        };
      }

      throw error;
    }
  }

  /**
   * Create a partial validator for a schema
   * @param schema Zod schema
   * @returns Partial schema
   */
  createPartialValidator<T extends z.ZodObject<any>>(schema: T): z.ZodObject<any> {
    return schema.partial();
  }

  /**
   * Create a deep partial validator for a schema
   * @param schema Zod schema
   * @returns Deep partial schema
   */
  createDeepPartialValidator<T extends z.ZodObject<any>>(schema: T): z.ZodObject<any> {
    return schema.deepPartial();
  }

  /**
   * Create a validator for an array of items
   * @param schema Item schema
   * @returns Array schema
   */
  createArrayValidator<T extends z.ZodType>(schema: T): z.ZodArray<T> {
    return z.array(schema);
  }

  /**
   * Create a validator with custom error messages
   * @param schema Zod schema
   * @param errorMap Custom error map
   * @returns Schema with custom error messages
   */
  createCustomErrorValidator<T extends z.ZodType>(schema: T, errorMap: z.ZodErrorMap): T {
    return schema.withErrorMap(errorMap);
  }

  /**
   * Validate asynchronously with custom error handling
   * @param schema Zod schema
   * @param data Input data
   * @param onSuccess Success callback
   * @param onError Error callback
   */
  async validateAsync<T extends z.ZodType, R>(
    schema: T,
    data: unknown,
    onSuccess: (validData: z.infer<T>) => Promise<R>,
    onError: (error: any) => Promise<R>
  ): Promise<R> {
    try {
      const validData = schema.parse(data);
      return await onSuccess(validData);
    } catch (error) {
      return await onError(error);
    }
  }

  /**
   * Create a refined schema with custom validation logic
   * @param schema Base schema
   * @param refinement Refinement function
   * @param message Error message
   * @returns Refined schema
   */
  refineSchema<T extends z.ZodType>(
    schema: T,
    refinement: (data: z.infer<T>) => boolean,
    message: string
  ): z.ZodEffects<T> {
    return schema.refine(refinement, { message });
  }

  /**
   * Create a schema that transforms the input
   * @param schema Base schema
   * @param transform Transform function
   * @returns Transformed schema
   */
  transformSchema<T extends z.ZodType, R>(
    schema: T,
    transform: (data: z.infer<T>) => R
  ): z.ZodEffects<T, R> {
    return schema.transform(transform);
  }

  /**
   * Create common validation schemas
   */
  schemas = {
    email: z.string().email('Invalid email address'),
    password: z.string().min(8, 'Password must be at least 8 characters'),
    uuid: z.string().uuid('Invalid UUID format'),
    url: z.string().url('Invalid URL format'),
    date: z.coerce.date(),
    nonEmptyString: z.string().min(1, 'Cannot be empty'),
    positiveNumber: z.number().positive('Must be a positive number'),
    phoneNumber: z.string().regex(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number format'),
    boolean: z.boolean(),
    nullableString: z.string().nullable(),
    optionalString: z.string().optional(),
  };
}

// Export singleton instance
export const validation = new ValidationService();

// Export individual functions for backward compatibility
export const validateConfig = validation.validateConfig.bind(validation);
export const validateInput = validation.validateInput.bind(validation);
export const createPartialValidator = validation.createPartialValidator.bind(validation);
