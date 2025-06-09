import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';
import { loadEncryptionConfig, encryptionConfigSchema } from './encryption.config';

// Initialize environment
env.initialize();

// Define OAuth config schema with Zod
const oauthConfigSchema = z.object({
  // Encryption configuration
  encryption: encryptionConfigSchema,
  authorizationCodeTtl: z
    .number()
    .int()
    .positive()
    .default(10 * 60), // 10 minutes
  accessTokenTtl: z
    .number()
    .int()
    .positive()
    .default(60 * 60), // 1 hour
  refreshTokenTtl: z
    .number()
    .int()
    .positive()
    .default(30 * 24 * 60 * 60), // 30 days
  idTokenTtl: z
    .number()
    .int()
    .positive()
    .default(60 * 60), // 1 hour
  jwtAlgorithm: z.string().default('RS256'),
  supportedResponseTypes: z
    .array(z.string())
    .default([
      'code',
      'token',
      'id_token',
      'code token',
      'code id_token',
      'token id_token',
      'code token id_token',
    ]),
  supportedGrantTypes: z
    .array(z.string())
    .default(['authorization_code', 'implicit', 'refresh_token', 'client_credentials', 'password']),
  supportedScopes: z
    .array(z.string())
    .default(['openid', 'profile', 'email', 'address', 'phone', 'offline_access']),
  supportedPkceTransformations: z.array(z.string()).default(['S256', 'plain']),
  requirePkce: z.boolean().default(true),
  allowImplicitFlow: z.boolean().default(true),
  allowClientCredentialsFlow: z.boolean().default(true),
  allowPasswordFlow: z.boolean().default(false),
  allowRefreshToken: z.boolean().default(true),
  rotateRefreshToken: z.boolean().default(true),
  issuer: z.string().default('https://auth.example.com'),
  jwksUri: z.string().default('https://auth.example.com/.well-known/jwks.json'),
  authorizationEndpoint: z.string().default('https://auth.example.com/oauth/authorize'),
  tokenEndpoint: z.string().default('https://auth.example.com/oauth/token'),
  userInfoEndpoint: z.string().default('https://auth.example.com/oauth/userinfo'),
  revocationEndpoint: z.string().default('https://auth.example.com/oauth/revoke'),
  introspectionEndpoint: z.string().default('https://auth.example.com/oauth/introspect'),
  endSessionEndpoint: z.string().default('https://auth.example.com/oauth/logout'),
  clients: z
    .array(
      z.object({
        clientId: z.string(),
        clientSecret: z.string().optional(),
        clientName: z.string(),
        redirectUris: z.array(z.string()),
        allowedGrantTypes: z.array(z.string()),
        allowedScopes: z.array(z.string()),
        requirePkce: z.boolean().optional(),
        requireClientSecret: z.boolean().optional(),
        tokenEndpointAuthMethod: z
          .enum([
            'client_secret_basic',
            'client_secret_post',
            'client_secret_jwt',
            'private_key_jwt',
            'none',
          ])
          .default('client_secret_basic'),
        accessTokenTtl: z.number().int().positive().optional(),
        refreshTokenTtl: z.number().int().positive().optional(),
        idTokenTtl: z.number().int().positive().optional(),
        allowedCorsOrigins: z.array(z.string()).optional(),
        enabled: z.boolean().default(true),
      })
    )
    .default([]),
  providers: z
    .array(
      z.object({
        name: z.string(),
        type: z.enum(['oauth2', 'oidc']),
        clientId: z.string(),
        clientSecret: z.string(),
        authorizationEndpoint: z.string(),
        tokenEndpoint: z.string(),
        userInfoEndpoint: z.string().optional(),
        jwksUri: z.string().optional(),
        issuer: z.string().optional(),
        scope: z.string().default('openid profile email'),
        enabled: z.boolean().default(true),
        userMapping: z.record(z.string()).optional(),
      })
    )
    .default([]),
});

// Load encryption configuration
const encryptionConfig = loadEncryptionConfig();

// Parse and validate environment variables
const rawConfig = {
  encryption: encryptionConfig,
  authorizationCodeTtl: env.getNumber('OAUTH_AUTHORIZATION_CODE_TTL'),
  accessTokenTtl: env.getNumber('OAUTH_ACCESS_TOKEN_TTL'),
  refreshTokenTtl: env.getNumber('OAUTH_REFRESH_TOKEN_TTL'),
  idTokenTtl: env.getNumber('OAUTH_ID_TOKEN_TTL'),
  jwtAlgorithm: env.get('OAUTH_JWT_ALGORITHM'),
  supportedResponseTypes: env.get('OAUTH_SUPPORTED_RESPONSE_TYPES')?.split(','),
  supportedGrantTypes: env.get('OAUTH_SUPPORTED_GRANT_TYPES')?.split(','),
  supportedScopes: env.get('OAUTH_SUPPORTED_SCOPES')?.split(','),
  supportedPkceTransformations: env.get('OAUTH_SUPPORTED_PKCE_TRANSFORMATIONS')?.split(','),
  requirePkce: env.getBoolean('OAUTH_REQUIRE_PKCE'),
  allowImplicitFlow: env.getBoolean('OAUTH_ALLOW_IMPLICIT_FLOW'),
  allowClientCredentialsFlow: env.getBoolean('OAUTH_ALLOW_CLIENT_CREDENTIALS_FLOW'),
  allowPasswordFlow: env.getBoolean('OAUTH_ALLOW_PASSWORD_FLOW'),
  allowRefreshToken: env.getBoolean('OAUTH_ALLOW_REFRESH_TOKEN'),
  rotateRefreshToken: env.getBoolean('OAUTH_ROTATE_REFRESH_TOKEN'),
  issuer: env.get('OAUTH_ISSUER'),
  jwksUri: env.get('OAUTH_JWKS_URI'),
  authorizationEndpoint: env.get('OAUTH_AUTHORIZATION_ENDPOINT'),
  tokenEndpoint: env.get('OAUTH_TOKEN_ENDPOINT'),
  userInfoEndpoint: env.get('OAUTH_USERINFO_ENDPOINT'),
  revocationEndpoint: env.get('OAUTH_REVOCATION_ENDPOINT'),
  introspectionEndpoint: env.get('OAUTH_INTROSPECTION_ENDPOINT'),
  endSessionEndpoint: env.get('OAUTH_END_SESSION_ENDPOINT'),
  clients: env.get('OAUTH_CLIENTS') ? JSON.parse(env.get('OAUTH_CLIENTS') as string) : [],
  providers: env.get('OAUTH_PROVIDERS') ? JSON.parse(env.get('OAUTH_PROVIDERS') as string) : [],
};

// Validate and export config
export const oauthConfig = validateConfig(oauthConfigSchema, rawConfig);

// Export config type
export type OAuthConfig = typeof oauthConfig;
