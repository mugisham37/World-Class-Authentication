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
}> {
  return await getDatabaseHealth();
}
