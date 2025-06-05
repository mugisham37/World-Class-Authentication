import { env } from './environment';
import { Prisma } from '@prisma/client';

/**
 * PostgreSQL configuration interface
 */
export interface PostgresConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  ssl: boolean;
  poolSize: number;
  idleTimeout: number;
  connectionTimeout: number;
  slowQueryThreshold: number;
  maxRetries: number;
  retryDelay: number;
}

/**
 * Redis configuration interface
 */
export interface RedisConfig {
  host: string;
  port: number;
  password?: string;
  db: number;
  keyPrefix: string;
  ttl: number;
  maxRetries: number;
  retryDelay: number;
  enableTLS: boolean;
  sessionStore: {
    enabled: boolean;
    prefix: string;
    ttl: number;
  };
  tokenStore: {
    enabled: boolean;
    prefix: string;
    ttl: number;
  };
  rateLimit: {
    enabled: boolean;
    prefix: string;
  };
}

/**
 * Prisma configuration interface
 */
export interface PrismaConfig {
  logLevel: Prisma.LogLevel[];
  errorFormat: string;
  queryLogLevel: string;
}

/**
 * Database configuration interface
 */
export interface DatabaseConfig {
  postgres: PostgresConfig;
  redis: RedisConfig;
  prisma: PrismaConfig;
  connectionPooling: {
    enabled: boolean;
    min: number;
    max: number;
    idleTimeoutMillis: number;
  };
  migrations: {
    autoRun: boolean;
    directory: string;
  };
}

/**
 * Database configuration
 */
export const databaseConfig = {
  postgres: {
    host: env.get('DB_HOST', 'localhost') || 'localhost',
    port: env.getNumber('DB_PORT', 5432) || 5432,
    database: env.get('DB_NAME', 'auth_db') || 'auth_db',
    user: env.get('DB_USER', 'postgres') || 'postgres',
    password: env.get('DB_PASSWORD', 'postgres') || 'postgres',
    ssl: env.getBoolean('DB_SSL', false) ?? false,
    poolSize: env.getNumber('DB_POOL_SIZE', 10) || 10,
    idleTimeout: env.getNumber('DB_IDLE_TIMEOUT', 30000) || 30000,
    connectionTimeout: env.getNumber('DB_CONNECTION_TIMEOUT', 5000) || 5000,
    slowQueryThreshold: env.getNumber('DB_SLOW_QUERY_THRESHOLD', 1000) || 1000,
    maxRetries: env.getNumber('DB_MAX_RETRIES', 5) || 5,
    retryDelay: env.getNumber('DB_RETRY_DELAY', 1000) || 1000,
  },
  redis: {
    host: env.get('REDIS_HOST', 'localhost') || 'localhost',
    port: env.getNumber('REDIS_PORT', 6379) || 6379,
    ...(env.has('REDIS_PASSWORD') ? { password: env.get('REDIS_PASSWORD') } : {}),
    db: env.getNumber('REDIS_DB', 0) || 0,
    keyPrefix: env.get('REDIS_KEY_PREFIX', 'auth:') || 'auth:',
    ttl: env.getNumber('REDIS_TTL', 86400) || 86400,
    maxRetries: env.getNumber('REDIS_MAX_RETRIES', 5) || 5,
    retryDelay: env.getNumber('REDIS_RETRY_DELAY', 1000) || 1000,
    enableTLS: env.getBoolean('REDIS_TLS', false) ?? false,
    sessionStore: {
      enabled: env.getBoolean('REDIS_SESSION_STORE_ENABLED', true) ?? true,
      prefix: env.get('REDIS_SESSION_PREFIX', 'auth:session:') || 'auth:session:',
      ttl: env.getNumber('REDIS_SESSION_TTL', 86400) || 86400, // 24 hours
    },
    tokenStore: {
      enabled: env.getBoolean('REDIS_TOKEN_STORE_ENABLED', true) ?? true,
      prefix: env.get('REDIS_TOKEN_PREFIX', 'auth:token:') || 'auth:token:',
      ttl: env.getNumber('REDIS_TOKEN_TTL', 604800) || 604800, // 7 days
    },
    rateLimit: {
      enabled: env.getBoolean('REDIS_RATE_LIMIT_ENABLED', true) ?? true,
      prefix: env.get('REDIS_RATE_LIMIT_PREFIX', 'auth:ratelimit:') || 'auth:ratelimit:',
    },
  },
  prisma: {
    logLevel: (env.get('PRISMA_LOG_LEVEL', 'warn') || 'warn').split(',') as Prisma.LogLevel[],
    errorFormat: env.get('PRISMA_ERROR_FORMAT', 'pretty') || 'pretty',
    queryLogLevel: env.get('PRISMA_QUERY_LOG_LEVEL', 'info') || 'info',
  },
  connectionPooling: {
    enabled: env.getBoolean('DB_POOL_ENABLED', true) ?? true,
    min: env.getNumber('DB_POOL_MIN', 2) || 2,
    max: env.getNumber('DB_POOL_MAX', 10) || 10,
    idleTimeoutMillis: env.getNumber('DB_POOL_IDLE_TIMEOUT', 30000) || 30000,
  },
  migrations: {
    autoRun: env.getBoolean('DB_MIGRATIONS_AUTO_RUN', true) ?? true,
    directory: env.get('DB_MIGRATIONS_DIRECTORY', './prisma/migrations') || './prisma/migrations',
  },
} as DatabaseConfig;

// Export alias for backward compatibility
export { databaseConfig as dbConfig };
