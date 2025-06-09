import { z } from 'zod';
import { logger } from '../infrastructure/logging/logger';
import { validateEnvVars } from '../utils/env-validator';

/**
 * Encryption configuration schema
 * Defines the validation schema for encryption configuration
 */
export const encryptionConfigSchema = z.object({
  secretKey: z.string().min(32, 'Secret key must be at least 32 characters long'),
  algorithm: z.string().default('aes-256-gcm'),
  ivLength: z.number().int().positive().default(16),
  authTagLength: z.number().int().positive().default(16),
});

/**
 * Encryption configuration type
 * TypeScript type definition for the encryption configuration
 */
export type EncryptionConfig = z.infer<typeof encryptionConfigSchema>;

/**
 * Default encryption configuration
 * Provides sensible defaults for all encryption configuration options
 * Note: secretKey has no default as it must be provided by the environment
 */
export const DEFAULT_ENCRYPTION_CONFIG: Omit<EncryptionConfig, 'secretKey'> = {
  algorithm: 'aes-256-gcm',
  ivLength: 16,
  authTagLength: 16,
};

/**
 * Load encryption configuration from environment variables
 * @returns Validated encryption configuration
 */
export function loadEncryptionConfig(): EncryptionConfig {
  try {
    // Define required and optional environment variables
    const requiredEnvVars: string[] = ['ENCRYPTION_SECRET_KEY'];
    const optionalEnvVars: string[] = [
      'ENCRYPTION_ALGORITHM',
      'ENCRYPTION_IV_LENGTH',
      'ENCRYPTION_AUTH_TAG_LENGTH',
    ];

    // Validate environment variables
    validateEnvVars(requiredEnvVars, optionalEnvVars);

    // Parse environment variables
    const encryptionConfig = {
      secretKey: process.env['ENCRYPTION_SECRET_KEY'] as string,
      algorithm: process.env['ENCRYPTION_ALGORITHM'] || DEFAULT_ENCRYPTION_CONFIG.algorithm,
      ivLength: parseInt(
        process.env['ENCRYPTION_IV_LENGTH'] || DEFAULT_ENCRYPTION_CONFIG.ivLength.toString(),
        10
      ),
      authTagLength: parseInt(
        process.env['ENCRYPTION_AUTH_TAG_LENGTH'] ||
          DEFAULT_ENCRYPTION_CONFIG.authTagLength.toString(),
        10
      ),
    };

    // Validate configuration
    const validatedConfig = encryptionConfigSchema.parse(encryptionConfig);

    // Log successful configuration loading
    logger.debug('Encryption configuration loaded successfully');

    return validatedConfig;
  } catch (error) {
    // Log error and rethrow
    logger.error('Failed to load encryption configuration', { error });

    if (error instanceof Error) {
      logger.error(error.message);
    }

    throw new Error('Invalid encryption configuration');
  }
}

/**
 * Validate encryption configuration
 * Helper function to validate an encryption configuration object
 *
 * @param config Encryption configuration to validate
 * @returns Validated encryption configuration
 */
export function validateEncryptionConfig(
  config: Partial<EncryptionConfig> & { secretKey: string }
): EncryptionConfig {
  try {
    // Merge with defaults for any missing properties
    const mergedConfig = {
      secretKey: config.secretKey,
      algorithm: config.algorithm || DEFAULT_ENCRYPTION_CONFIG.algorithm,
      ivLength: config.ivLength || DEFAULT_ENCRYPTION_CONFIG.ivLength,
      authTagLength: config.authTagLength || DEFAULT_ENCRYPTION_CONFIG.authTagLength,
    };

    // Validate the merged configuration
    return encryptionConfigSchema.parse(mergedConfig);
  } catch (error) {
    // Log validation error and throw
    logger.error('Encryption configuration validation failed', { error });
    throw error;
  }
}
