import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';

/**
 * Prisma client singleton
 */
class PrismaClientManager {
  private static instance: PrismaClient;
  private static isInitialized = false;

  /**
   * Get the Prisma client instance
   * Creates a new instance if one doesn't exist
   */
  public static getInstance(): PrismaClient {
    if (!PrismaClientManager.instance) {
      PrismaClientManager.instance = new PrismaClient({
        log: [
          { level: 'query', emit: 'event' },
          { level: 'error', emit: 'event' },
          { level: 'info', emit: 'event' },
          { level: 'warn', emit: 'event' },
        ],
      });

      // Set up logging for Prisma events
      PrismaClientManager.setupLogging();
    }
    return PrismaClientManager.instance;
  }

  /**
   * Set up logging for Prisma events
   */
  private static setupLogging(): void {
    const prisma = PrismaClientManager.instance;

    // Log queries
    prisma.$on('query', (e: { query: string; params: string; duration: number }) => {
      logger.debug('Prisma query', {
        query: e.query,
        params: e.params,
        duration: e.duration,
      });
    });

    // Log errors
    prisma.$on('error', (e: Error) => {
      logger.error('Prisma error', { error: e });
    });

    // Log info
    prisma.$on('info', (e: string) => {
      logger.info('Prisma info', { message: e });
    });

    // Log warnings
    prisma.$on('warn', (e: string) => {
      logger.warn('Prisma warning', { message: e });
    });
  }

  /**
   * Connect to the database
   */
  public static async connect(): Promise<void> {
    try {
      const prisma = PrismaClientManager.getInstance();
      await prisma.$connect();
      PrismaClientManager.isInitialized = true;
      logger.info('Prisma client connected to database');
    } catch (error) {
      logger.error('Failed to connect Prisma client to database', { error });
      throw new DatabaseError(
        'Failed to connect Prisma client to database',
        'PRISMA_CONNECTION_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Disconnect from the database
   */
  public static async disconnect(): Promise<void> {
    if (!PrismaClientManager.isInitialized || !PrismaClientManager.instance) {
      return;
    }

    try {
      await PrismaClientManager.instance.$disconnect();
      PrismaClientManager.isInitialized = false;
      logger.info('Prisma client disconnected from database');
    } catch (error) {
      logger.error('Error disconnecting Prisma client from database', { error });
      throw new DatabaseError(
        'Error disconnecting Prisma client from database',
        'PRISMA_DISCONNECT_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check if the Prisma client is connected
   */
  public static isConnected(): boolean {
    return PrismaClientManager.isInitialized;
  }

  /**
   * Check the health of the Prisma client
   */
  public static async healthCheck(): Promise<{ status: string; details?: string }> {
    try {
      const prisma = PrismaClientManager.getInstance();

      // Execute a simple query to check the connection
      await prisma.$queryRaw`SELECT 1`;

      return {
        status: 'ok',
        details: 'Prisma client is connected to the database',
      };
    } catch (error) {
      logger.error('Prisma health check failed', { error });
      return {
        status: 'error',
        details: `Failed to connect to database: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }
}

// Export the Prisma client instance
export const prisma = PrismaClientManager.getInstance();

// Export connection methods
export const connectDatabase = PrismaClientManager.connect;
export const disconnectDatabase = PrismaClientManager.disconnect;
export const isDatabaseConnected = PrismaClientManager.isConnected;
export const checkDatabaseHealth = PrismaClientManager.healthCheck;
