import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define app config schema with Zod
const appConfigSchema = z.object({
  app: z.object({
    name: z.string().default('World-Class-Authentication'),
    environment: z.enum(['development', 'test', 'production']).default('development'),
    port: z.number().int().positive().default(3000),
    apiPrefix: z.string().default('/api/v1'),
    url: z.string().url().optional(),
  }),
  auth: z.object({
    enabled: z.boolean().default(true),
    registrationEnabled: z.boolean().default(true),
    loginPath: z.string().default('/auth/login'),
    registerPath: z.string().default('/auth/register'),
    logoutPath: z.string().default('/auth/logout'),
    refreshTokenPath: z.string().default('/auth/refresh'),
    verifyEmailPath: z.string().default('/auth/verify-email'),
    resetPasswordPath: z.string().default('/auth/reset-password'),
    changePasswordPath: z.string().default('/auth/change-password'),
    sessionInfoPath: z.string().default('/auth/session'),
    defaultRedirectPath: z.string().default('/dashboard'),
    loginRedirectParam: z.string().default('redirect'),
  }),
  logging: z.object({
    level: z.enum(['error', 'warn', 'info', 'http', 'debug']).default('info'),
    format: z.enum(['json', 'pretty']).default('pretty'),
    enableConsole: z.boolean().default(true),
    enableFile: z.boolean().default(false),
    filePath: z.string().optional(),
  }),
  cors: z.object({
    origin: z.union([z.string(), z.array(z.string())]).default('*'),
    methods: z.array(z.string()).default(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']),
    allowedHeaders: z.array(z.string()).default(['Content-Type', 'Authorization']),
    exposedHeaders: z.array(z.string()).default([]),
    credentials: z.boolean().default(true),
    maxAge: z.number().int().positive().default(86400),
  }),
  rateLimiting: z.object({
    windowMs: z
      .number()
      .int()
      .positive()
      .default(15 * 60 * 1000), // 15 minutes
    max: z.number().int().positive().default(100), // 100 requests per windowMs
  }),
  swagger: z.object({
    enabled: z.boolean().default(true),
    title: z.string().default('World-Class-Authentication API'),
    description: z.string().default('API documentation for World-Class-Authentication'),
    version: z.string().default('1.0.0'),
    path: z.string().default('/api-docs'),
  }),
});

// Parse and validate environment variables
const rawConfig = {
  app: {
    name: env.get('APP_NAME'),
    environment: env.get('NODE_ENV'),
    port: env.getNumber('PORT'),
    apiPrefix: env.get('API_PREFIX'),
    url: env.get('APP_URL'),
  },
  auth: {
    enabled: env.getBoolean('AUTH_ENABLED'),
    registrationEnabled: env.getBoolean('AUTH_REGISTRATION_ENABLED'),
    loginPath: env.get('AUTH_LOGIN_PATH'),
    registerPath: env.get('AUTH_REGISTER_PATH'),
    logoutPath: env.get('AUTH_LOGOUT_PATH'),
    refreshTokenPath: env.get('AUTH_REFRESH_TOKEN_PATH'),
    verifyEmailPath: env.get('AUTH_VERIFY_EMAIL_PATH'),
    resetPasswordPath: env.get('AUTH_RESET_PASSWORD_PATH'),
    changePasswordPath: env.get('AUTH_CHANGE_PASSWORD_PATH'),
    sessionInfoPath: env.get('AUTH_SESSION_INFO_PATH'),
    defaultRedirectPath: env.get('AUTH_DEFAULT_REDIRECT_PATH'),
    loginRedirectParam: env.get('AUTH_LOGIN_REDIRECT_PARAM'),
  },
  logging: {
    level: env.get('LOG_LEVEL'),
    format: env.get('LOG_FORMAT'),
    enableConsole: env.getBoolean('LOG_ENABLE_CONSOLE'),
    enableFile: env.getBoolean('LOG_ENABLE_FILE'),
    filePath: env.get('LOG_FILE_PATH'),
  },
  cors: {
    origin: env.get('CORS_ORIGIN'),
    methods: env.get('CORS_METHODS')?.split(','),
    allowedHeaders: env.get('CORS_ALLOWED_HEADERS')?.split(','),
    exposedHeaders: env.get('CORS_EXPOSED_HEADERS')?.split(','),
    credentials: env.getBoolean('CORS_CREDENTIALS'),
    maxAge: env.getNumber('CORS_MAX_AGE'),
  },
  rateLimiting: {
    windowMs: env.getNumber('RATE_LIMIT_WINDOW_MS'),
    max: env.getNumber('RATE_LIMIT_MAX'),
  },
  swagger: {
    enabled: env.getBoolean('SWAGGER_ENABLED'),
    title: env.get('SWAGGER_TITLE'),
    description: env.get('SWAGGER_DESCRIPTION'),
    version: env.get('SWAGGER_VERSION'),
    path: env.get('SWAGGER_PATH'),
  },
};

// Validate and export config
export const appConfig = validateConfig(appConfigSchema, rawConfig);

// Export config type
export type AppConfig = typeof appConfig;
