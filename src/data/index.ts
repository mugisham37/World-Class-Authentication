// Export database connections
import {
  connectDatabase,
  disconnectDatabase,
  isDatabaseConnected,
  checkDatabaseHealth as checkPrismaHealth,
} from './prisma/client';

import {
  connectPostgres,
  disconnectPostgres,
  getPostgresStatus,
  query,
  transaction,
  pool,
} from './connections/postgres';

import {
  connectRedis,
  disconnectRedis,
  getRedisStatus,
  isRedisConnected,
  redisCache,
} from './connections/redis';

import { metricsCollector } from './connections/metrics-collector';

import {
  createQueryBuilder,
  db as queryBuilder,
  QueryBuilder,
  QueryBuilderOptions,
} from './connections/query-builder';

import { ConnectionWrapper, db } from './connections/connection-wrapper';

import {
  ConnectionMonitor,
  connectionMonitor,
  ConnectionHealth,
  ConnectionMonitorOptions,
} from './connections/connection-monitor';

import {
  initializeDatabase,
  shutdownDatabase,
  getDatabaseHealth,
  isDatabaseConnected as isDbConnected,
} from './connections/database-manager';

// Export repositories
import { repositories } from './repositories';

// Export models
import * as UserModels from './models/user.model';

// Database connections
export {
  // Prisma
  connectDatabase,
  disconnectDatabase,
  isDatabaseConnected,
  checkPrismaHealth,

  // PostgreSQL
  connectPostgres,
  disconnectPostgres,
  getPostgresStatus,
  query,
  transaction,
  pool,

  // Redis
  connectRedis,
  disconnectRedis,
  getRedisStatus,
  isRedisConnected,
  redisCache,

  // Metrics
  metricsCollector,

  // Query Builder
  createQueryBuilder,
  queryBuilder,
  QueryBuilder,
  QueryBuilderOptions,

  // Connection Wrapper
  ConnectionWrapper,
  db,

  // Connection Monitor
  ConnectionMonitor,
  connectionMonitor,
  ConnectionHealth,
  ConnectionMonitorOptions,

  // Database manager
  initializeDatabase,
  shutdownDatabase,
  getDatabaseHealth,
  isDbConnected,
};

// Repositories
export { repositories };

// Models
export { UserModels };

/**
 * Initialize the data layer
 * This function should be called at application startup
 */
export async function initializeDataLayer(): Promise<void> {
  await initializeDatabase();
}

/**
 * Shutdown the data layer
 * This function should be called at application shutdown
 */
export async function shutdownDataLayer(): Promise<void> {
  await shutdownDatabase();
}

/**
 * Check the health of the data layer
 * @returns Object with status and details for each database connection
 */
export async function checkDataLayerHealth(): Promise<{
  status: string;
  prisma: { status: string; details?: string };
  postgres: { status: string; details?: string };
  redis: { status: string; details?: string };
}> {
  return await getDatabaseHealth();
}
