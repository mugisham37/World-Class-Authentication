import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  connectDatabase,
  disconnectDatabase,
  checkDatabaseHealth as checkPrismaHealth,
} from '../prisma/client';
import { connectPostgres, disconnectPostgres, getPostgresStatus } from './postgres';

/**
 * Database connection manager
 * Handles connections to all database systems used by the application
 */
export class DatabaseManager {
  private static isInitialized = false;

  /**
   * Initialize all database connections
   * @returns Promise that resolves when all connections are established
   */
  public static async initialize(): Promise<void> {
    if (DatabaseManager.isInitialized) {
      logger.warn('Database connections already initialized');
      return;
    }

    try {
      logger.info('Initializing database connections...');

      // Connect to Prisma
      await connectDatabase();

      // Connect to PostgreSQL
      await connectPostgres();

      DatabaseManager.isInitialized = true;
      logger.info('All database connections initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize database connections', { error });
      throw new DatabaseError(
        'Failed to initialize database connections',
        'DATABASE_INITIALIZATION_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Close all database connections
   * @returns Promise that resolves when all connections are closed
   */
  public static async shutdown(): Promise<void> {
    if (!DatabaseManager.isInitialized) {
      logger.warn('Database connections not initialized, nothing to shut down');
      return;
    }

    try {
      logger.info('Shutting down database connections...');

      // Disconnect from Prisma
      await disconnectDatabase();

      // Disconnect from PostgreSQL
      await disconnectPostgres();

      DatabaseManager.isInitialized = false;
      logger.info('All database connections shut down successfully');
    } catch (error) {
      logger.error('Error shutting down database connections', { error });
      throw new DatabaseError(
        'Error shutting down database connections',
        'DATABASE_SHUTDOWN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check the health of all database connections
   * @returns Object with status and details for each database connection
   */
  public static async healthCheck(): Promise<{
    status: string;
    prisma: { status: string; details?: string };
    postgres: { status: string; details?: string };
  }> {
    try {
      // Check Prisma health
      const prismaStatus = await checkPrismaHealth();

      // Check PostgreSQL health
      const postgresStatus = await getPostgresStatus();

      // Determine overall status
      const overallStatus =
        prismaStatus.status === 'ok' && postgresStatus.status === 'ok' ? 'ok' : 'error';

      return {
        status: overallStatus,
        prisma: prismaStatus,
        postgres: postgresStatus,
      };
    } catch (error) {
      logger.error('Error checking database health', { error });
      return {
        status: 'error',
        prisma: { status: 'error', details: 'Failed to check Prisma health' },
        postgres: { status: 'error', details: 'Failed to check PostgreSQL health' },
      };
    }
  }

  /**
   * Check if database connections are initialized
   * @returns True if initialized, false otherwise
   */
  public static isConnected(): boolean {
    return DatabaseManager.isInitialized;
  }
}

// Export convenience methods
export const initializeDatabase = DatabaseManager.initialize;
export const shutdownDatabase = DatabaseManager.shutdown;
export const getDatabaseHealth = DatabaseManager.healthCheck;
export const isDatabaseConnected = DatabaseManager.isConnected;
