import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define security config schema with Zod
const securityConfigSchema = z.object({
  jwt: z.object({
    accessTokenSecret: z.string().min(32),
    refreshTokenSecret: z.string().min(32),
    accessTokenExpiresIn: z.string().default('15m'), // 15 minutes
    refreshTokenExpiresIn: z.string().default('7d'), // 7 days
    issuer: z.string().default('auth-system'),
    audience: z.string().default('auth-system-client'),
  }),
  password: z.object({
    saltRounds: z.number().int().positive().default(12),
    pepper: z.string().min(32).optional(),
    minLength: z.number().int().positive().default(8),
    requireLowercase: z.boolean().default(true),
    requireUppercase: z.boolean().default(true),
    requireNumbers: z.boolean().default(true),
    requireSymbols: z.boolean().default(true),
    maxHistory: z.number().int().nonnegative().default(5),
  }),
  session: z.object({
    cookieName: z.string().default('auth.session'),
    cookieSecure: z.boolean().default(true),
    cookieHttpOnly: z.boolean().default(true),
    cookieSameSite: z.enum(['strict', 'lax', 'none']).default('strict'),
    cookiePath: z.string().default('/'),
    cookieMaxAge: z
      .number()
      .int()
      .positive()
      .default(86400 * 1000), // 24 hours
    absoluteTimeout: z
      .number()
      .int()
      .positive()
      .default(8 * 60 * 60 * 1000), // 8 hours
    idleTimeout: z
      .number()
      .int()
      .positive()
      .default(15 * 60 * 1000), // 15 minutes
  }),
  rateLimit: z.object({
    login: z.object({
      windowMs: z
        .number()
        .int()
        .positive()
        .default(15 * 60 * 1000), // 15 minutes
      max: z.number().int().positive().default(5), // 5 attempts per windowMs
      skipSuccessfulRequests: z.boolean().default(true),
    }),
    registration: z.object({
      windowMs: z
        .number()
        .int()
        .positive()
        .default(60 * 60 * 1000), // 1 hour
      max: z.number().int().positive().default(3), // 3 attempts per windowMs
    }),
    passwordReset: z.object({
      windowMs: z
        .number()
        .int()
        .positive()
        .default(60 * 60 * 1000), // 1 hour
      max: z.number().int().positive().default(3), // 3 attempts per windowMs
    }),
  }),
  encryption: z.object({
    algorithm: z.string().default('aes-256-gcm'),
    secretKey: z.string().min(32),
    ivLength: z.number().int().positive().default(16),
    masterKey: z.string().min(64).optional(),
    keyDerivationIterations: z.number().int().positive().default(100000),
  }),
  csrf: z.object({
    enabled: z.boolean().default(true),
    secret: z.string().min(32).optional(),
    cookieName: z.string().default('_csrf'),
    headerName: z.string().default('X-CSRF-Token'),
  }),
});

// Parse and validate environment variables
const rawConfig = {
  jwt: {
    accessTokenSecret: env.get('JWT_ACCESS_TOKEN_SECRET'),
    refreshTokenSecret: env.get('JWT_REFRESH_TOKEN_SECRET'),
    accessTokenExpiresIn: env.get('JWT_ACCESS_TOKEN_EXPIRES_IN'),
    refreshTokenExpiresIn: env.get('JWT_REFRESH_TOKEN_EXPIRES_IN'),
    issuer: env.get('JWT_ISSUER'),
    audience: env.get('JWT_AUDIENCE'),
  },
  password: {
    saltRounds: env.getNumber('PASSWORD_SALT_ROUNDS'),
    pepper: env.get('PASSWORD_PEPPER'),
    minLength: env.getNumber('PASSWORD_MIN_LENGTH'),
    requireLowercase: env.getBoolean('PASSWORD_REQUIRE_LOWERCASE'),
    requireUppercase: env.getBoolean('PASSWORD_REQUIRE_UPPERCASE'),
    requireNumbers: env.getBoolean('PASSWORD_REQUIRE_NUMBERS'),
    requireSymbols: env.getBoolean('PASSWORD_REQUIRE_SYMBOLS'),
    maxHistory: env.getNumber('PASSWORD_MAX_HISTORY'),
  },
  session: {
    cookieName: env.get('SESSION_COOKIE_NAME'),
    cookieSecure: env.getBoolean('SESSION_COOKIE_SECURE'),
    cookieHttpOnly: env.getBoolean('SESSION_COOKIE_HTTP_ONLY'),
    cookieSameSite: env.get('SESSION_COOKIE_SAME_SITE') as 'strict' | 'lax' | 'none',
    cookiePath: env.get('SESSION_COOKIE_PATH'),
    cookieMaxAge: env.getNumber('SESSION_COOKIE_MAX_AGE'),
    absoluteTimeout: env.getNumber('SESSION_ABSOLUTE_TIMEOUT'),
    idleTimeout: env.getNumber('SESSION_IDLE_TIMEOUT'),
  },
  rateLimit: {
    login: {
      windowMs: env.getNumber('RATE_LIMIT_LOGIN_WINDOW_MS'),
      max: env.getNumber('RATE_LIMIT_LOGIN_MAX'),
      skipSuccessfulRequests: env.getBoolean('RATE_LIMIT_LOGIN_SKIP_SUCCESSFUL'),
    },
    registration: {
      windowMs: env.getNumber('RATE_LIMIT_REGISTRATION_WINDOW_MS'),
      max: env.getNumber('RATE_LIMIT_REGISTRATION_MAX'),
    },
    passwordReset: {
      windowMs: env.getNumber('RATE_LIMIT_PASSWORD_RESET_WINDOW_MS'),
      max: env.getNumber('RATE_LIMIT_PASSWORD_RESET_MAX'),
    },
  },
  encryption: {
    algorithm: env.get('ENCRYPTION_ALGORITHM'),
    secretKey: env.get('ENCRYPTION_SECRET_KEY'),
    ivLength: env.getNumber('ENCRYPTION_IV_LENGTH'),
  },
  csrf: {
    enabled: env.getBoolean('CSRF_ENABLED'),
    secret: env.get('CSRF_SECRET'),
    cookieName: env.get('CSRF_COOKIE_NAME'),
    headerName: env.get('CSRF_HEADER_NAME'),
  },
};

// Validate and export config
export const securityConfig = validateConfig(securityConfigSchema, rawConfig);

// Export config type
export type SecurityConfig = typeof securityConfig;
