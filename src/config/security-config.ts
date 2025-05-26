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
  security: z.object({
    maxFailedLoginAttempts: z.number().int().positive().default(5),
    accountLockoutDurationMinutes: z.number().int().positive().default(30),
    passwordExpiryDays: z.number().int().nonnegative().default(90), // 0 means never expire
    requireEmailVerification: z.boolean().default(true),
    mfaEnabled: z.boolean().default(false),
    sessionConcurrencyLimit: z.number().int().positive().default(5),
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
  risk: z.object({
    enabled: z.boolean().default(true),
    thresholds: z.object({
      low: z.number().int().nonnegative().default(25),
      medium: z.number().int().nonnegative().default(50),
      high: z.number().int().nonnegative().default(75),
    }),
    actions: z.object({
      low: z.enum(['allow', 'challenge', 'block']).default('allow'),
      medium: z.enum(['allow', 'challenge', 'block']).default('allow'),
      high: z.enum(['allow', 'challenge', 'block']).default('challenge'),
      critical: z.enum(['allow', 'challenge', 'block']).default('block'),
    }),
    ipReputationEnabled: z.boolean().default(true),
    behavioralAnalysisEnabled: z.boolean().default(true),
    locationAnalysisEnabled: z.boolean().default(true),
    timeAnalysisEnabled: z.boolean().default(true),
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
  security: {
    maxFailedLoginAttempts: env.getNumber('SECURITY_MAX_FAILED_LOGIN_ATTEMPTS'),
    accountLockoutDurationMinutes: env.getNumber('SECURITY_ACCOUNT_LOCKOUT_DURATION'),
    passwordExpiryDays: env.getNumber('SECURITY_PASSWORD_EXPIRY_DAYS'),
    requireEmailVerification: env.getBoolean('SECURITY_REQUIRE_EMAIL_VERIFICATION'),
    mfaEnabled: env.getBoolean('SECURITY_MFA_ENABLED'),
    sessionConcurrencyLimit: env.getNumber('SECURITY_SESSION_CONCURRENCY_LIMIT'),
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
  risk: {
    enabled: env.getBoolean('RISK_ENABLED'),
    thresholds: {
      low: env.getNumber('RISK_THRESHOLD_LOW'),
      medium: env.getNumber('RISK_THRESHOLD_MEDIUM'),
      high: env.getNumber('RISK_THRESHOLD_HIGH'),
    },
    actions: {
      low: env.get('RISK_ACTION_LOW') as 'allow' | 'challenge' | 'block',
      medium: env.get('RISK_ACTION_MEDIUM') as 'allow' | 'challenge' | 'block',
      high: env.get('RISK_ACTION_HIGH') as 'allow' | 'challenge' | 'block',
      critical: env.get('RISK_ACTION_CRITICAL') as 'allow' | 'challenge' | 'block',
    },
    ipReputationEnabled: env.getBoolean('RISK_IP_REPUTATION_ENABLED'),
    behavioralAnalysisEnabled: env.getBoolean('RISK_BEHAVIORAL_ANALYSIS_ENABLED'),
    locationAnalysisEnabled: env.getBoolean('RISK_LOCATION_ANALYSIS_ENABLED'),
    timeAnalysisEnabled: env.getBoolean('RISK_TIME_ANALYSIS_ENABLED'),
  },
};

// Validate and export config
export const securityConfig = validateConfig(securityConfigSchema, rawConfig);

// Export config type
export type SecurityConfig = typeof securityConfig;
