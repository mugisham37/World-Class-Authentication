/**
 * Custom error class for passwordless session operations
 */
export class PasswordlessSessionError extends Error {
  constructor(
    message: string,
    public code: string,
    public originalError?: Error
  ) {
    super(message);
    this.name = 'PasswordlessSessionError';
  }
}
