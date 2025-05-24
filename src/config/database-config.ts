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
 * Prisma configuration
 */
export interface PrismaConfig {
  url: string;
  logQueries: boolean;
  logSlowQueries: boolean;
  slowQueryThreshold: number;
}

/**
 * Database configuration
 */
export interface DatabaseConfig {
  postgres: PostgresConfig;
  prisma: PrismaConfig;
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
  prisma: {
    url: env.get('DATABASE_URL') || 'postgresql://postgres:postgres@localhost:5432/auth_db',
    logQueries: env.getBoolean('PRISMA_LOG_QUERIES') || false,
    logSlowQueries: env.getBoolean('PRISMA_LOG_SLOW_QUERIES') || true,
    slowQueryThreshold: env.getNumber('PRISMA_SLOW_QUERY_THRESHOLD') || 1000,
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
 * Get Prisma configuration
 * @returns Prisma configuration
 */
export function getPrismaConfig(): PrismaConfig {
  return dbConfig.prisma;
}
