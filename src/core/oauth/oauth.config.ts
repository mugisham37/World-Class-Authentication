import { z } from 'zod';
import { logger } from '../../infrastructure/logging/logger';
import { validateEnvVars } from '../../utils/env-validator';
import { loadTokenConfig, TokenConfig, tokenConfigSchema } from './token.config';

/**
 * TypeScript type definitions for environment variables
 * This improves type safety when accessing process.env
 */
declare global {
  namespace NodeJS {
    interface ProcessEnv {
      JWT_SECRET?: string;
      OAUTH_AUTHORIZATION_CODE_TTL?: string;
      OAUTH_ACCESS_TOKEN_TTL?: string;
      OAUTH_REFRESH_TOKEN_TTL?: string;
      OAUTH_ID_TOKEN_TTL?: string;
      OAUTH_JWT_ALGORITHM?: string;
      OAUTH_REQUIRE_PKCE?: string;
      OAUTH_ALLOW_IMPLICIT_FLOW?: string;
      OAUTH_ALLOW_CLIENT_CREDENTIALS_FLOW?: string;
      OAUTH_ALLOW_PASSWORD_FLOW?: string;
      OAUTH_ALLOW_REFRESH_TOKEN?: string;
      OAUTH_ROTATE_REFRESH_TOKEN?: string;
      OAUTH_ISSUER?: string;
      OAUTH_JWKS_URI?: string;
      OAUTH_AUTHORIZATION_ENDPOINT?: string;
      OAUTH_TOKEN_ENDPOINT?: string;
      OAUTH_USERINFO_ENDPOINT?: string;
      OAUTH_REVOCATION_ENDPOINT?: string;
      OAUTH_INTROSPECTION_ENDPOINT?: string;
      OAUTH_END_SESSION_ENDPOINT?: string;
      OAUTH_REGISTRATION_ENDPOINT?: string;
      OAUTH_SUPPORTED_SCOPES?: string;
      OAUTH_DEFAULT_SCOPES?: string;
      OAUTH_ALLOWED_GRANT_TYPES?: string;
      OAUTH_ALLOWED_RESPONSE_TYPES?: string;
      OAUTH_ALLOWED_SCOPES?: string;
      OAUTH_SUPPORTED_PKCE_TRANSFORMATIONS?: string;
      OAUTH_DYNAMIC_REGISTRATION?: string;
      OAUTH_JWT_ACCESS_TOKENS?: string;
      OAUTH_REFRESH_TOKEN_ROTATION?: string;
    }
  }
}

/**
 * OAuth configuration schema
 * Defines the validation schema for OAuth configuration
 */
export const oauthConfigSchema = z.object({
  // Authorization code settings
  authorizationCode: z.object({
    ttl: z.number().int().positive().default(600), // 10 minutes
  }),

  // Token settings
  tokens: z.object({
    accessToken: z.object({
      ttl: z.number().int().positive().default(3600), // 1 hour
      algorithm: z.string().default('RS256'),
      expiresIn: z.number().int().positive().default(3600), // 1 hour
      secret: z.string().optional(),
    }),
    refreshToken: z.object({
      ttl: z.number().int().positive().default(2592000), // 30 days
      rotation: z.boolean().default(true),
      expiresIn: z.number().int().positive().default(2592000), // 30 days
      length: z.number().int().positive().default(64), // Length in characters
      rotationWindow: z.number().int().positive().default(86400), // 1 day in seconds
    }),
    idToken: z.object({
      ttl: z.number().int().positive().default(3600), // 1 hour
      expiresIn: z.number().int().positive().default(3600), // 1 hour
    }),
    authorizationCode: z.object({
      expiresIn: z.number().int().positive().default(600), // 10 minutes
    }),
  }),

  // Flow settings
  flows: z.object({
    authorizationCode: z.object({
      enabled: z.boolean().default(true),
      requirePkce: z.boolean().default(true),
    }),
    implicit: z.object({
      enabled: z.boolean().default(true),
    }),
    clientCredentials: z.object({
      enabled: z.boolean().default(true),
    }),
    password: z.object({
      enabled: z.boolean().default(false),
    }),
    refreshToken: z.object({
      enabled: z.boolean().default(true),
    }),
  }),

  // Endpoint settings
  endpoints: z.object({
    issuer: z.string().url().default('https://auth.example.com'),
    jwksUri: z.string().url().default('https://auth.example.com/.well-known/jwks.json'),
    authorization: z.string().url().default('https://auth.example.com/oauth/authorize'),
    token: z.string().url().default('https://auth.example.com/oauth/token'),
    userInfo: z.string().url().default('https://auth.example.com/oauth/userinfo'),
    revocation: z.string().url().default('https://auth.example.com/oauth/revoke'),
    introspection: z.string().url().default('https://auth.example.com/oauth/introspect'),
    endSession: z.string().url().default('https://auth.example.com/oauth/logout'),
  }),

  // Scope settings
  scopes: z.object({
    supported: z
      .array(z.string())
      .default(['openid', 'profile', 'email', 'address', 'phone', 'offline_access']),
    default: z.array(z.string()).default(['openid', 'profile', 'email']),
  }),

  // PKCE settings
  pkce: z.object({
    supportedTransformations: z.array(z.string()).default(['S256', 'plain']),
  }),

  // Server settings
  server: z.object({
    issuer: z.string().default('https://auth.example.com'),
    registrationEndpoint: z.string().default('/oauth/register'),
  }),

  // Client settings
  clients: z.object({
    dynamicRegistration: z.boolean().default(false),
    allowedGrantTypes: z
      .array(z.string())
      .default(['authorization_code', 'refresh_token', 'client_credentials']),
    allowedResponseTypes: z.array(z.string()).default(['code', 'token', 'id_token']),
    defaultScopes: z.array(z.string()).default(['openid', 'profile', 'email']),
    allowedScopes: z
      .array(z.string())
      .default(['openid', 'profile', 'email', 'address', 'phone', 'offline_access']),
  }),

  // Feature flags
  features: z.object({
    jwtAccessTokens: z.boolean().default(true),
    refreshTokenRotation: z.boolean().default(true),
  }),
});

/**
 * OAuth configuration type
 * TypeScript type definition for the OAuth configuration
 */
export type OAuthConfig = z.infer<typeof oauthConfigSchema>;

/**
 * Default OAuth configuration
 * Provides sensible defaults for all OAuth configuration options
 */
export const DEFAULT_OAUTH_CONFIG: OAuthConfig = {
  authorizationCode: {
    ttl: 600, // 10 minutes
  },
  tokens: {
    accessToken: {
      ttl: 3600, // 1 hour
      algorithm: 'RS256',
      expiresIn: 3600, // 1 hour
      secret: process.env['JWT_SECRET'] || 'default-secret',
    },
    refreshToken: {
      ttl: 2592000, // 30 days
      rotation: true,
      expiresIn: 2592000, // 30 days
      length: 64, // Length in characters
      rotationWindow: 86400, // 1 day in seconds
    },
    idToken: {
      ttl: 3600, // 1 hour
      expiresIn: 3600, // 1 hour
    },
    authorizationCode: {
      expiresIn: 600, // 10 minutes
    },
  },
  flows: {
    authorizationCode: {
      enabled: true,
      requirePkce: true,
    },
    implicit: {
      enabled: true,
    },
    clientCredentials: {
      enabled: true,
    },
    password: {
      enabled: false,
    },
    refreshToken: {
      enabled: true,
    },
  },
  endpoints: {
    issuer: 'https://auth.example.com',
    jwksUri: 'https://auth.example.com/.well-known/jwks.json',
    authorization: 'https://auth.example.com/oauth/authorize',
    token: 'https://auth.example.com/oauth/token',
    userInfo: 'https://auth.example.com/oauth/userinfo',
    revocation: 'https://auth.example.com/oauth/revoke',
    introspection: 'https://auth.example.com/oauth/introspect',
    endSession: 'https://auth.example.com/oauth/logout',
  },
  scopes: {
    supported: ['openid', 'profile', 'email', 'address', 'phone', 'offline_access'],
    default: ['openid', 'profile', 'email'],
  },
  pkce: {
    supportedTransformations: ['S256', 'plain'],
  },
  server: {
    issuer: 'https://auth.example.com',
    registrationEndpoint: '/oauth/register',
  },
  clients: {
    dynamicRegistration: false,
    allowedGrantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
    allowedResponseTypes: ['code', 'token', 'id_token'],
    defaultScopes: ['openid', 'profile', 'email'],
    allowedScopes: ['openid', 'profile', 'email', 'address', 'phone', 'offline_access'],
  },
  features: {
    jwtAccessTokens: true,
    refreshTokenRotation: true,
  },
};

/**
 * Load OAuth configuration from environment variables
 * @returns Validated OAuth configuration
 */
export function loadOAuthConfig(): OAuthConfig {
  try {
    // Define required and optional environment variables
    const requiredEnvVars: string[] = [];
    const optionalEnvVars: string[] = [
      'OAUTH_AUTHORIZATION_CODE_TTL',
      'OAUTH_ACCESS_TOKEN_TTL',
      'OAUTH_REFRESH_TOKEN_TTL',
      'OAUTH_ID_TOKEN_TTL',
      'OAUTH_JWT_ALGORITHM',
      'OAUTH_REQUIRE_PKCE',
      'OAUTH_ALLOW_IMPLICIT_FLOW',
      'OAUTH_ALLOW_CLIENT_CREDENTIALS_FLOW',
      'OAUTH_ALLOW_PASSWORD_FLOW',
      'OAUTH_ALLOW_REFRESH_TOKEN',
      'OAUTH_ROTATE_REFRESH_TOKEN',
      'OAUTH_ISSUER',
      'OAUTH_JWKS_URI',
      'OAUTH_AUTHORIZATION_ENDPOINT',
      'OAUTH_TOKEN_ENDPOINT',
      'OAUTH_USERINFO_ENDPOINT',
      'OAUTH_REVOCATION_ENDPOINT',
      'OAUTH_INTROSPECTION_ENDPOINT',
      'OAUTH_END_SESSION_ENDPOINT',
      'OAUTH_SUPPORTED_SCOPES',
      'OAUTH_DEFAULT_SCOPES',
      'OAUTH_SUPPORTED_PKCE_TRANSFORMATIONS',
    ];

    // Validate environment variables
    validateEnvVars(requiredEnvVars, optionalEnvVars);

    // Load token configuration
    const tokenConfig = loadTokenConfig();

    // Parse environment variables
    const oauthConfig = {
      authorizationCode: {
        ttl: parseInt(process.env['OAUTH_AUTHORIZATION_CODE_TTL'] || '600', 10),
      },
      tokens: {
        accessToken: {
          ttl: parseInt(process.env['OAUTH_ACCESS_TOKEN_TTL'] || '3600', 10),
          algorithm: process.env['OAUTH_JWT_ALGORITHM'] || 'RS256',
          expiresIn: tokenConfig.accessToken.expiresIn,
          secret: process.env['JWT_SECRET'] || 'default-secret',
        },
        refreshToken: {
          ttl: parseInt(process.env['OAUTH_REFRESH_TOKEN_TTL'] || '2592000', 10),
          rotation: process.env['OAUTH_ROTATE_REFRESH_TOKEN'] === 'true',
          expiresIn: tokenConfig.refreshToken.expiresIn,
          length: tokenConfig.refreshToken.length,
          rotationWindow: tokenConfig.refreshToken.rotationWindow,
        },
        idToken: {
          ttl: parseInt(process.env['OAUTH_ID_TOKEN_TTL'] || '3600', 10),
          expiresIn: tokenConfig.idToken.expiresIn,
        },
        authorizationCode: {
          expiresIn: parseInt(process.env['OAUTH_AUTHORIZATION_CODE_TTL'] || '600', 10),
        },
      },
      flows: {
        authorizationCode: {
          enabled: true,
          requirePkce: process.env['OAUTH_REQUIRE_PKCE'] === 'true',
        },
        implicit: {
          enabled: process.env['OAUTH_ALLOW_IMPLICIT_FLOW'] === 'true',
        },
        clientCredentials: {
          enabled: process.env['OAUTH_ALLOW_CLIENT_CREDENTIALS_FLOW'] === 'true',
        },
        password: {
          enabled: process.env['OAUTH_ALLOW_PASSWORD_FLOW'] === 'true',
        },
        refreshToken: {
          enabled: process.env['OAUTH_ALLOW_REFRESH_TOKEN'] === 'true',
        },
      },
      endpoints: {
        issuer: process.env['OAUTH_ISSUER'] || 'https://auth.example.com',
        jwksUri: process.env['OAUTH_JWKS_URI'] || 'https://auth.example.com/.well-known/jwks.json',
        authorization:
          process.env['OAUTH_AUTHORIZATION_ENDPOINT'] || 'https://auth.example.com/oauth/authorize',
        token: process.env['OAUTH_TOKEN_ENDPOINT'] || 'https://auth.example.com/oauth/token',
        userInfo:
          process.env['OAUTH_USERINFO_ENDPOINT'] || 'https://auth.example.com/oauth/userinfo',
        revocation:
          process.env['OAUTH_REVOCATION_ENDPOINT'] || 'https://auth.example.com/oauth/revoke',
        introspection:
          process.env['OAUTH_INTROSPECTION_ENDPOINT'] ||
          'https://auth.example.com/oauth/introspect',
        endSession:
          process.env['OAUTH_END_SESSION_ENDPOINT'] || 'https://auth.example.com/oauth/logout',
      },
      scopes: {
        supported: process.env['OAUTH_SUPPORTED_SCOPES']?.split(',') || [
          'openid',
          'profile',
          'email',
          'address',
          'phone',
          'offline_access',
        ],
        default: process.env['OAUTH_DEFAULT_SCOPES']?.split(',') || ['openid', 'profile', 'email'],
      },
      pkce: {
        supportedTransformations: process.env['OAUTH_SUPPORTED_PKCE_TRANSFORMATIONS']?.split(
          ','
        ) || ['S256', 'plain'],
      },
      server: {
        issuer: process.env['OAUTH_ISSUER'] || 'https://auth.example.com',
        registrationEndpoint: process.env['OAUTH_REGISTRATION_ENDPOINT'] || '/oauth/register',
      },
      clients: {
        dynamicRegistration: process.env['OAUTH_DYNAMIC_REGISTRATION'] === 'true',
        allowedGrantTypes: process.env['OAUTH_ALLOWED_GRANT_TYPES']?.split(',') || [
          'authorization_code',
          'refresh_token',
          'client_credentials',
        ],
        allowedResponseTypes: process.env['OAUTH_ALLOWED_RESPONSE_TYPES']?.split(',') || [
          'code',
          'token',
          'id_token',
        ],
        defaultScopes: process.env['OAUTH_DEFAULT_SCOPES']?.split(',') || [
          'openid',
          'profile',
          'email',
        ],
        allowedScopes: process.env['OAUTH_ALLOWED_SCOPES']?.split(',') || [
          'openid',
          'profile',
          'email',
          'address',
          'phone',
          'offline_access',
        ],
      },
      features: {
        jwtAccessTokens: process.env['OAUTH_JWT_ACCESS_TOKENS'] === 'true',
        refreshTokenRotation: process.env['OAUTH_REFRESH_TOKEN_ROTATION'] === 'true',
      },
    };

    // Validate configuration
    const validatedConfig = oauthConfigSchema.parse(oauthConfig);

    // Log successful configuration loading
    logger.debug('OAuth configuration loaded successfully');

    return validatedConfig;
  } catch (error) {
    // Log error and use default configuration
    logger.error('Failed to load OAuth configuration, using defaults', { error });

    if (error instanceof Error) {
      logger.error(error.message);
    }

    return DEFAULT_OAUTH_CONFIG;
  }
}

/**
 * Validate OAuth configuration
 * Helper function to validate an OAuth configuration object
 *
 * @param config OAuth configuration to validate
 * @returns Validated OAuth configuration
 */
export function validateOAuthConfig(config: Partial<OAuthConfig>): OAuthConfig {
  try {
    // Merge with defaults for any missing properties
    const mergedConfig = {
      authorizationCode: {
        ...DEFAULT_OAUTH_CONFIG.authorizationCode,
        ...config.authorizationCode,
      },
      tokens: {
        accessToken: {
          ...DEFAULT_OAUTH_CONFIG.tokens.accessToken,
          ...config.tokens?.accessToken,
        },
        refreshToken: {
          ...DEFAULT_OAUTH_CONFIG.tokens.refreshToken,
          ...config.tokens?.refreshToken,
        },
        idToken: {
          ...DEFAULT_OAUTH_CONFIG.tokens.idToken,
          ...config.tokens?.idToken,
        },
      },
      flows: {
        authorizationCode: {
          ...DEFAULT_OAUTH_CONFIG.flows.authorizationCode,
          ...config.flows?.authorizationCode,
        },
        implicit: {
          ...DEFAULT_OAUTH_CONFIG.flows.implicit,
          ...config.flows?.implicit,
        },
        clientCredentials: {
          ...DEFAULT_OAUTH_CONFIG.flows.clientCredentials,
          ...config.flows?.clientCredentials,
        },
        password: {
          ...DEFAULT_OAUTH_CONFIG.flows.password,
          ...config.flows?.password,
        },
        refreshToken: {
          ...DEFAULT_OAUTH_CONFIG.flows.refreshToken,
          ...config.flows?.refreshToken,
        },
      },
      endpoints: {
        ...DEFAULT_OAUTH_CONFIG.endpoints,
        ...config.endpoints,
      },
      scopes: {
        ...DEFAULT_OAUTH_CONFIG.scopes,
        ...config.scopes,
      },
      pkce: {
        ...DEFAULT_OAUTH_CONFIG.pkce,
        ...config.pkce,
      },
    };

    // Validate the merged configuration
    return oauthConfigSchema.parse(mergedConfig);
  } catch (error) {
    // Log validation error and throw
    logger.error('OAuth configuration validation failed', { error });
    throw error;
  }
}

/**
 * Export an instance of the OAuth configuration
 * This is used by services that need access to the configuration
 */
export const oauthConfig = loadOAuthConfig();
