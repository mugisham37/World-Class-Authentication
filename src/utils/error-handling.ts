/**
 * Base application error
 * All application errors should extend this class
 */
export class AppError extends Error {
  /**
   * Error code
   */
  public readonly code: string;

  /**
   * Original error
   */
  public readonly originalError: Error | undefined;

  /**
   * Constructor
   * @param message Error message
   * @param code Error code
   * @param originalError Original error
   */
  constructor(message: string, code: string, originalError: Error | undefined = undefined) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.originalError = originalError;

    // Capture stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/**
 * Database error
 * Thrown when a database operation fails
 */
export class DatabaseError extends AppError {
  /**
   * Constructor
   * @param message Error message
   * @param code Error code
   * @param originalError Original error
   */
  constructor(message: string, code: string, originalError?: Error) {
    super(message, code, originalError);
  }
}

/**
 * Not found error
 * Thrown when a resource is not found
 */
export class NotFoundError extends AppError {
  /**
   * Constructor
   * @param message Error message
   * @param code Error code
   * @param originalError Original error
   */
  constructor(message: string, code: string = 'RESOURCE_NOT_FOUND', originalError?: Error) {
    super(message, code, originalError);
  }
}

/**
 * Validation error
 * Thrown when validation fails
 */
export class ValidationError extends AppError {
  /**
   * Validation errors
   */
  public readonly errors: Record<string, string[]>;

  /**
   * Constructor
   * @param message Error message
   * @param errors Validation errors
   * @param code Error code
   * @param originalError Original error
   */
  constructor(
    message: string,
    errors: Record<string, string[]>,
    code: string = 'VALIDATION_ERROR',
    originalError?: Error
  ) {
    super(message, code, originalError);
    this.errors = errors;
  }
}

/**
 * Authentication error
 * Thrown when authentication fails
 */
export class AuthenticationError extends AppError {
  /**
   * Constructor
   * @param message Error message
   * @param code Error code
   * @param originalError Original error
   */
  constructor(message: string, code: string = 'AUTHENTICATION_ERROR', originalError?: Error) {
    super(message, code, originalError);
  }
}

/**
 * Authorization error
 * Thrown when authorization fails
 */
export class AuthorizationError extends AppError {
  /**
   * Constructor
   * @param message Error message
   * @param code Error code
   * @param originalError Original error
   */
  constructor(message: string, code: string = 'AUTHORIZATION_ERROR', originalError?: Error) {
    super(message, code, originalError);
  }
}

/**
 * Conflict error
 * Thrown when a conflict occurs
 */
export class ConflictError extends AppError {
  /**
   * Constructor
   * @param message Error message
   * @param code Error code
   * @param originalError Original error
   */
  constructor(message: string, code: string = 'CONFLICT_ERROR', originalError?: Error) {
    super(message, code, originalError);
  }
}

/**
 * Rate limit error
 * Thrown when a rate limit is exceeded
 */
export class RateLimitError extends AppError {
  /**
   * Constructor
   * @param message Error message
   * @param code Error code
   * @param originalError Original error
   */
  constructor(message: string, code: string = 'RATE_LIMIT_ERROR', originalError?: Error) {
    super(message, code, originalError);
  }
}

/**
 * Too many requests error
 * Thrown when too many requests are made in a short period
 */
export class TooManyRequestsError extends AppError {
  /**
   * Constructor
   * @param message Error message
   * @param code Error code
   * @param originalError Original error
   */
  constructor(message: string, code: string = 'TOO_MANY_REQUESTS', originalError?: Error) {
    super(message, code, originalError);
  }
}

/**
 * External service error
 * Thrown when an external service fails
 */
export class ExternalServiceError extends AppError {
  /**
   * Constructor
   * @param message Error message
   * @param code Error code
   * @param originalError Original error
   */
  constructor(message: string, code: string = 'EXTERNAL_SERVICE_ERROR', originalError?: Error) {
    super(message, code, originalError);
  }
}

/**
 * Check if an error is an instance of AppError
 * @param error Error to check
 * @returns True if the error is an instance of AppError
 */
export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError;
}

/**
 * Error details interface
 */
export interface ErrorDetails {
  message: string;
  code: string;
  stack: string | undefined;
  originalError: Error | undefined;
}

/**
 * Get error details
 * @param error Error to get details from
 * @returns Error details
 */
export function getErrorDetails(error: unknown): ErrorDetails {
  if (isAppError(error)) {
    return {
      message: error.message,
      code: error.code,
      stack: error.stack,
      originalError: error.originalError,
    };
  }

  if (error instanceof Error) {
    return {
      message: error.message,
      code: 'UNKNOWN_ERROR',
      stack: error.stack,
      originalError: undefined,
    };
  }

  return {
    message: String(error),
    code: 'UNKNOWN_ERROR',
    stack: undefined,
    originalError: undefined,
  };
}
