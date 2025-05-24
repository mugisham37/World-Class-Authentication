import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  connectDatabase,
  disconnectDatabase,
  checkDatabaseHealth as checkPrismaHealth,
} from '../prisma/client';
import { connectPostgres, disconnectPostgres, getPostgresStatus } from './postgres';
import { connectRedis, disconnectRedis, getRedisStatus } from './redis';
import { metricsCollector } from './metrics-collector';
import { connectionMonitor } from './connection-monitor';

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

      // Connect to Redis
      await connectRedis();

      // Start metrics collection
      metricsCollector.startCollecting();
      logger.info('Database metrics collection started');

      // Start connection monitoring
      connectionMonitor.start();
      logger.info('Database connection monitoring started');

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

      // Disconnect from Redis
      await disconnectRedis();

      // Stop metrics collection
      metricsCollector.stopCollecting();
      logger.info('Database metrics collection stopped');

      // Stop connection monitoring
      connectionMonitor.stop();
      logger.info('Database connection monitoring stopped');

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
    redis: { status: string; details?: string };
  }> {
    try {
      // Check Prisma health
      const prismaStatus = await checkPrismaHealth();

      // Check PostgreSQL health
      const postgresStatus = await getPostgresStatus();

      // Check Redis health
      const redisStatus = await getRedisStatus();

      // Determine overall status
      const overallStatus =
        prismaStatus.status === 'ok' &&
        postgresStatus.status === 'ok' &&
        redisStatus.status === 'ok'
          ? 'ok'
          : 'error';

      return {
        status: overallStatus,
        prisma: prismaStatus,
        postgres: postgresStatus,
        redis: redisStatus,
      };
    } catch (error) {
      logger.error('Error checking database health', { error });
      return {
        status: 'error',
        prisma: { status: 'error', details: 'Failed to check Prisma health' },
        postgres: { status: 'error', details: 'Failed to check PostgreSQL health' },
        redis: { status: 'error', details: 'Failed to check Redis health' },
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
