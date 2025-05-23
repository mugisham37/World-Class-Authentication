import { z } from 'zod';

/**
 * Validates configuration against a Zod schema
 *
 * This utility function takes a Zod schema and raw configuration data,
 * validates the data against the schema, and returns the validated and
 * type-safe configuration object.
 *
 * If validation fails, it logs detailed error messages and exits the process
 * to prevent the application from running with invalid configuration.
 *
 * @param schema The Zod schema to validate against
 * @param config The raw configuration data to validate
 * @returns The validated and type-safe configuration object
 */
export function validateConfig<T extends z.ZodType>(schema: T, config: any): z.infer<T> {
  try {
    // Parse and validate the configuration
    return schema.parse(config);
  } catch (error) {
    if (error instanceof z.ZodError) {
      console.error('\n❌ Configuration validation failed:');

      // Format and log each validation error
      error.errors.forEach(err => {
        const path = err.path.join('.');
        console.error(`  - ${path}: ${err.message}`);
      });

      // Provide guidance on fixing the errors
      console.error(
        '\nPlease check your environment variables and ensure they match the expected types.'
      );
      console.error('The application cannot start with invalid configuration.\n');

      // Exit the process to prevent running with invalid configuration
      process.exit(1);
    }

    // Re-throw unexpected errors
    throw error;
  }
}

/**
 * Validates user input against a Zod schema
 *
 * This utility function is similar to validateConfig but designed for
 * validating user input in API requests. Instead of exiting the process,
 * it throws a formatted error that can be caught and handled by API error
 * middleware.
 *
 * @param schema The Zod schema to validate against
 * @param data The user input data to validate
 * @returns The validated and type-safe data
 * @throws Formatted validation error object
 */
export function validateInput<T extends z.ZodType>(schema: T, data: any): z.infer<T> {
  try {
    return schema.parse(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      // Transform Zod errors into a more API-friendly format
      const formattedErrors = error.errors.reduce(
        (acc, err) => {
          const path = err.path.join('.');
          acc[path] = err.message;
          return acc;
        },
        {} as Record<string, string>
      );

      // Throw a formatted error object that can be caught by API error middleware
      throw {
        status: 400,
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        errors: formattedErrors,
      };
    }

    throw error;
  }
}

/**
 * Creates a partial validator for a Zod schema
 *
 * This utility function takes a Zod schema and returns a new schema where
 * all properties are optional. This is useful for validating partial updates
 * to resources.
 *
 * @param schema The Zod schema to make partial
 * @returns A new Zod schema where all properties are optional
 */
export function createPartialValidator<T extends z.ZodType>(schema: T): z.ZodObject<any> {
  if (schema instanceof z.ZodObject) {
    return schema.partial();
  }
  throw new Error('Schema must be a Zod object schema');
}
