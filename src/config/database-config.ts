import { env } from './environment';

/**
 * PostgreSQL configuration
 */
export interface PostgresConfig {
  host: string;
  port: number;
  username: string;
  password: string;
  database: string;
  ssl: boolean;
  poolSize: number;
  idleTimeoutMillis: number;
  connectionTimeoutMillis: number;
}

/**
 * Redis configuration
 */
export interface RedisConfig {
  host: string;
  port: number;
  password?: string | undefined;
  db: number;
  keyPrefix: string;
  connectionTimeoutMillis: number;
  maxRetriesPerRequest: number;
  enableOfflineQueue: boolean;
  enableReadyCheck: boolean;
}

/**
 * Prisma configuration
 */
export interface PrismaConfig {
  url: string;
  logQueries: boolean;
  logSlowQueries: boolean;
  slowQueryThreshold: number;
}

/**
 * Metrics configuration
 */
export interface MetricsConfig {
  enabled: boolean;
  collectionInterval: number;
  maxDataPoints: number;
  logMetrics: boolean;
}

/**
 * Database configuration
 */
export interface DatabaseConfig {
  postgres: PostgresConfig;
  redis: RedisConfig;
  prisma: PrismaConfig;
  metrics: MetricsConfig;
}

/**
 * Database configuration
 */
export const dbConfig: DatabaseConfig = {
  postgres: {
    host: env.get('POSTGRES_HOST') || 'localhost',
    port: env.getNumber('POSTGRES_PORT') || 5432,
    username: env.get('POSTGRES_USER') || 'postgres',
    password: env.get('POSTGRES_PASSWORD') || 'postgres',
    database: env.get('POSTGRES_DB') || 'auth_db',
    ssl: env.getBoolean('POSTGRES_SSL') || false,
    poolSize: env.getNumber('POSTGRES_POOL_SIZE') || 10,
    idleTimeoutMillis: env.getNumber('POSTGRES_IDLE_TIMEOUT') || 30000,
    connectionTimeoutMillis: env.getNumber('POSTGRES_CONNECTION_TIMEOUT') || 5000,
  },
  redis: {
    host: env.get('REDIS_HOST') || 'localhost',
    port: env.getNumber('REDIS_PORT') || 6379,
    password: env.get('REDIS_PASSWORD'),
    db: env.getNumber('REDIS_DB') || 0,
    keyPrefix: env.get('REDIS_KEY_PREFIX') || 'auth:',
    connectionTimeoutMillis: env.getNumber('REDIS_CONNECTION_TIMEOUT') || 5000,
    maxRetriesPerRequest: env.getNumber('REDIS_MAX_RETRIES') || 3,
    enableOfflineQueue: env.getBoolean('REDIS_ENABLE_OFFLINE_QUEUE') || true,
    enableReadyCheck: env.getBoolean('REDIS_ENABLE_READY_CHECK') || true,
  },
  prisma: {
    url: env.get('DATABASE_URL') || 'postgresql://postgres:postgres@localhost:5432/auth_db',
    logQueries: env.getBoolean('PRISMA_LOG_QUERIES') || false,
    logSlowQueries: env.getBoolean('PRISMA_LOG_SLOW_QUERIES') || true,
    slowQueryThreshold: env.getNumber('PRISMA_SLOW_QUERY_THRESHOLD') || 1000,
  },
  metrics: {
    enabled: env.getBoolean('DB_METRICS_ENABLED') || true,
    collectionInterval: env.getNumber('DB_METRICS_INTERVAL') || 60000,
    maxDataPoints: env.getNumber('DB_METRICS_MAX_DATAPOINTS') || 1000,
    logMetrics: env.getBoolean('DB_METRICS_LOG') || false,
  },
};

/**
 * Get database configuration
 * @returns Database configuration
 */
export function getDatabaseConfig(): DatabaseConfig {
  return dbConfig;
}

/**
 * Get PostgreSQL configuration
 * @returns PostgreSQL configuration
 */
export function getPostgresConfig(): PostgresConfig {
  return dbConfig.postgres;
}

/**
 * Get Redis configuration
 * @returns Redis configuration
 */
export function getRedisConfig(): RedisConfig {
  return dbConfig.redis;
}

/**
 * Get Prisma configuration
 * @returns Prisma configuration
 */
export function getPrismaConfig(): PrismaConfig {
  return dbConfig.prisma;
}
