/**
 * Environment variable validation utility
 * This utility helps ensure that all required environment variables are present
 */

/**
 * Validates that all required environment variables are present
 * @param requiredVars Array of required environment variable names
 * @throws Error if any required variables are missing
 */
export function validateRequiredEnvVars(requiredVars: string[]): void {
  const missing = requiredVars.filter(key => process.env[key] === undefined);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}

/**
 * Validates that all required environment variables are present and logs a warning for optional variables that are missing
 * @param requiredVars Array of required environment variable names
 * @param optionalVars Array of optional environment variable names
 * @throws Error if any required variables are missing
 */
export function validateEnvVars(requiredVars: string[], optionalVars: string[] = []): void {
  // Check required variables
  validateRequiredEnvVars(requiredVars);
  
  // Check optional variables and log warnings
  const missingOptional = optionalVars.filter(key => process.env[key] === undefined);
  
  if (missingOptional.length > 0) {
    console.warn(`Warning: Missing optional environment variables: ${missingOptional.join(', ')}`);
  }
}
