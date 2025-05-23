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
