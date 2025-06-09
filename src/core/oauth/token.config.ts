import { z } from 'zod';
import { logger } from '../../infrastructure/logging/logger';
import { validateEnvVars } from '../../utils/env-validator';

/**
 * Token configuration schema
 * Defines the validation schema for token configuration
 */
export const tokenConfigSchema = z.object({
  accessToken: z.object({
    expiresIn: z.number().int().positive().default(3600), // 1 hour in seconds
  }),
  refreshToken: z.object({
    expiresIn: z.number().int().positive().default(2592000), // 30 days in seconds
    length: z.number().int().positive().default(64), // Length in characters
    rotationWindow: z.number().int().positive().default(86400), // 1 day in seconds
  }),
  idToken: z.object({
    expiresIn: z.number().int().positive().default(3600), // 1 hour in seconds
  }),
});

/**
 * Token configuration type
 * TypeScript type definition for the token configuration
 */
export type TokenConfig = z.infer<typeof tokenConfigSchema>;

/**
 * Default token configuration
 * Provides sensible defaults for all token configuration options
 */
export const DEFAULT_TOKEN_CONFIG: TokenConfig = {
  accessToken: {
    expiresIn: 3600, // 1 hour in seconds
  },
  refreshToken: {
    expiresIn: 2592000, // 30 days in seconds
    length: 64, // Length in characters
    rotationWindow: 86400, // 1 day in seconds
  },
  idToken: {
    expiresIn: 3600, // 1 hour in seconds
  },
};

/**
 * Load token configuration from environment variables
 * @returns Validated token configuration
 */
export function loadTokenConfig(): TokenConfig {
  try {
    // Define required and optional environment variables
    const requiredEnvVars: string[] = [];
    const optionalEnvVars: string[] = [
      'ACCESS_TOKEN_EXPIRES_IN',
      'REFRESH_TOKEN_EXPIRES_IN',
      'REFRESH_TOKEN_LENGTH',
      'REFRESH_TOKEN_ROTATION_WINDOW',
      'ID_TOKEN_EXPIRES_IN',
    ];

    // Validate environment variables
    validateEnvVars(requiredEnvVars, optionalEnvVars);

    // Parse environment variables
    const tokenConfig = {
      accessToken: {
        expiresIn: parseInt(process.env['ACCESS_TOKEN_EXPIRES_IN'] || '3600', 10),
      },
      refreshToken: {
        expiresIn: parseInt(process.env['REFRESH_TOKEN_EXPIRES_IN'] || '2592000', 10),
        length: parseInt(process.env['REFRESH_TOKEN_LENGTH'] || '64', 10),
        rotationWindow: parseInt(process.env['REFRESH_TOKEN_ROTATION_WINDOW'] || '86400', 10),
      },
      idToken: {
        expiresIn: parseInt(process.env['ID_TOKEN_EXPIRES_IN'] || '3600', 10),
      },
    };

    // Validate configuration
    const validatedConfig = tokenConfigSchema.parse(tokenConfig);

    // Log successful configuration loading
    logger.debug('Token configuration loaded successfully');

    return validatedConfig;
  } catch (error) {
    // Log error and use default configuration
    logger.error('Failed to load token configuration, using defaults', { error });

    if (error instanceof Error) {
      logger.error(error.message);
    }

    return DEFAULT_TOKEN_CONFIG;
  }
}

/**
 * Validate token configuration
 * Helper function to validate a token configuration object
 *
 * @param config Token configuration to validate
 * @returns Validated token configuration
 */
export function validateTokenConfig(config: Partial<TokenConfig>): TokenConfig {
  try {
    // Merge with defaults for any missing properties
    const mergedConfig = {
      accessToken: {
        ...DEFAULT_TOKEN_CONFIG.accessToken,
        ...config.accessToken,
      },
      refreshToken: {
        ...DEFAULT_TOKEN_CONFIG.refreshToken,
        ...config.refreshToken,
      },
      idToken: {
        ...DEFAULT_TOKEN_CONFIG.idToken,
        ...config.idToken,
      },
    };

    // Validate the merged configuration
    return tokenConfigSchema.parse(mergedConfig);
  } catch (error) {
    // Log validation error and throw
    logger.error('Token configuration validation failed', { error });
    throw error;
  }
}
