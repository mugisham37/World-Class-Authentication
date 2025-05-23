import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define database config schema with Zod
const databaseConfigSchema = z.object({
  postgres: z.object({
    url: z.string().url().optional(),
    host: z.string().default('localhost'),
    port: z.number().int().positive().default(5432),
    username: z.string(),
    password: z.string(),
    database: z.string(),
    ssl: z.boolean().default(false),
    poolSize: z.number().int().positive().default(10),
    idleTimeoutMillis: z.number().int().positive().default(30000),
    connectionTimeoutMillis: z.number().int().positive().default(2000),
  }),
  redis: z.object({
    url: z.string().url().optional(),
    host: z.string().default('localhost'),
    port: z.number().int().positive().default(6379),
    password: z.string().optional(),
    db: z.number().int().nonnegative().default(0),
    keyPrefix: z.string().default('auth:'),
    ttl: z.number().int().positive().default(86400), // 24 hours
  }),
  prisma: z.object({
    logLevel: z.enum(['error', 'warn', 'info', 'query']).default('error'),
    logQueries: z.boolean().default(false),
  }),
  migrations: z.object({
    autoRun: z.boolean().default(true),
    lockTimeoutMs: z.number().int().positive().default(10000),
  }),
});

// Parse and validate environment variables
const rawConfig = {
  postgres: {
    url: env.get('DATABASE_URL'),
    host: env.get('POSTGRES_HOST'),
    port: env.getNumber('POSTGRES_PORT'),
    username: env.get('POSTGRES_USER'),
    password: env.get('POSTGRES_PASSWORD'),
    database: env.get('POSTGRES_DB'),
    ssl: env.getBoolean('POSTGRES_SSL'),
    poolSize: env.getNumber('POSTGRES_POOL_SIZE'),
    idleTimeoutMillis: env.getNumber('POSTGRES_IDLE_TIMEOUT'),
    connectionTimeoutMillis: env.getNumber('POSTGRES_CONNECTION_TIMEOUT'),
  },
  redis: {
    url: env.get('REDIS_URL'),
    host: env.get('REDIS_HOST'),
    port: env.getNumber('REDIS_PORT'),
    password: env.get('REDIS_PASSWORD'),
    db: env.getNumber('REDIS_DB'),
    keyPrefix: env.get('REDIS_KEY_PREFIX'),
    ttl: env.getNumber('REDIS_TTL'),
  },
  prisma: {
    logLevel: env.get('PRISMA_LOG_LEVEL') as 'error' | 'warn' | 'info' | 'query',
    logQueries: env.getBoolean('PRISMA_LOG_QUERIES'),
  },
  migrations: {
    autoRun: env.getBoolean('DB_MIGRATIONS_AUTO_RUN'),
    lockTimeoutMs: env.getNumber('DB_MIGRATIONS_LOCK_TIMEOUT'),
  },
};

// Validate and export config
export const dbConfig = validateConfig(databaseConfigSchema, rawConfig);

// Export config type
export type DatabaseConfig = typeof dbConfig;
