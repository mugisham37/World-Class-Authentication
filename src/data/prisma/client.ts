import { PrismaClient, Prisma } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import { ExtendedPrismaClient as ExtendedPrismaClientType } from './prisma-types';

// Use Prisma's event types
type QueryEvent = Prisma.QueryEvent;
type LogEvent = Prisma.LogEvent;

/**
 * PrismaClient wrapper with properly typed events
 * Implements the ExtendedPrismaClientType to ensure all Prisma models are accessible
 */
export class ExtendedPrismaClient implements ExtendedPrismaClientType {
  private prisma: PrismaClient;

  constructor() {
    this.prisma = new PrismaClient({
      log: [
        { level: 'query', emit: 'event' },
        { level: 'error', emit: 'event' },
        { level: 'info', emit: 'event' },
        { level: 'warn', emit: 'event' },
      ],
    });

    // Set up event handlers
    this.setupEventHandlers();
  }

  /**
   * Set up event handlers for Prisma events
   */
  private setupEventHandlers() {
    // We'll set these up in the PrismaClientManager
  }

  /**
   * Register an event handler for Prisma query events
   */
  $on(event: 'query', callback: (event: QueryEvent) => void): void;
  /**
   * Register an event handler for Prisma log events
   */
  $on(event: 'info' | 'warn' | 'error', callback: (event: LogEvent) => void): void;
  /**
   * Implementation of the $on method
   */
  $on(event: string, callback: (event: any) => void): void {
    // Use type assertion to bypass TypeScript's type checking
    // This is safe because we're controlling the event types through our method overloads
    (this.prisma as any).$on(event, callback);
  }

  /**
   * Connect to the database
   */
  async $connect(): Promise<void> {
    return this.prisma.$connect();
  }

  /**
   * Disconnect from the database
   */
  async $disconnect(): Promise<void> {
    return this.prisma.$disconnect();
  }

  /**
   * Execute a raw query
   */
  async $queryRaw<T = unknown>(
    query: TemplateStringsArray | Prisma.Sql,
    ...values: any[]
  ): Promise<T> {
    return this.prisma.$queryRaw(query, ...values);
  }

  /**
   * Execute a function within a transaction
   * @param fn The function to execute within the transaction
   * @param options Optional transaction options
   * @returns The result of the function
   */
  async $transaction<R>(
    fn: (prisma: ExtendedPrismaClient) => Promise<R>,
    options?: {
      maxWait?: number;
      timeout?: number;
      isolationLevel?: 'ReadUncommitted' | 'ReadCommitted' | 'RepeatableRead' | 'Serializable';
    }
  ): Promise<R> {
    // Create transaction options object
    const txOptions: any = {};

    if (options?.maxWait) {
      txOptions.maxWait = options.maxWait;
    }

    if (options?.timeout) {
      txOptions.timeout = options.timeout;
    }

    if (options?.isolationLevel) {
      txOptions.isolationLevel = options.isolationLevel;
    }

    // Execute the transaction
    return this.prisma.$transaction(async tx => {
      // Create a transaction-scoped client
      const txClient = new ExtendedPrismaClient();
      // Replace its Prisma instance with the transaction
      (txClient as any).prisma = tx;
      // Execute the provided function
      return fn(txClient);
    }, txOptions);
  }

  /**
   * Access to the underlying PrismaClient instance
   * Use this for model operations (e.g., prisma.user.findMany())
   */
  get client(): PrismaClient {
    return this.prisma;
  }

  /**
   * Access to the credential model
   * This ensures TypeScript recognizes the credential property
   */
  get credential() {
    return this.prisma.credential;
  }

  /**
   * Access to the adminApproval model
   * This ensures TypeScript recognizes the adminApproval property
   */
  get adminApproval() {
    return this.prisma.adminApproval;
  }

  /**
   * Access to the auditLog model
   * This ensures TypeScript recognizes the auditLog property
   */
  get auditLog() {
    return this.prisma.auditLog;
  }

  /**
   * Access to the mfaChallenge model
   * This ensures TypeScript recognizes the mfaChallenge property
   */
  get mfaChallenge() {
    return this.prisma.mfaChallenge;
  }

  /**
   * Access to the mfaFactor model
   * This ensures TypeScript recognizes the mfaFactor property
   */
  get mfaFactor() {
    return this.prisma.mfaFactor;
  }

  /**
   * Access to the passwordHistory model
   * This ensures TypeScript recognizes the passwordHistory property
   */
  get passwordHistory() {
    return this.prisma.passwordHistory;
  }

  /**
   * Access to the user model
   * This ensures TypeScript recognizes the user property
   */
  get user() {
    return this.prisma.user;
  }

  /**
   * Access to the session model
   * This ensures TypeScript recognizes the session property
   */
  get session() {
    return this.prisma.session;
  }

  /**
   * Access to the userProfile model
   * This ensures TypeScript recognizes the userProfile property
   */
  get userProfile() {
    return this.prisma.userProfile;
  }

  /**
   * Forward any other method calls to the underlying PrismaClient
   */
  [key: string]: any;
}

/**
 * Prisma client singleton
 */
class PrismaClientManager {
  private static instance: ExtendedPrismaClient;
  private static isInitialized = false;

  /**
   * Get the Prisma client instance
   * Creates a new instance if one doesn't exist
   */
  public static getInstance(): ExtendedPrismaClient {
    if (!PrismaClientManager.instance) {
      PrismaClientManager.instance = new ExtendedPrismaClient();

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
    prisma.$on('query', (e: QueryEvent) => {
      logger.debug('Prisma query', {
        query: e.query,
        params: e.params,
        duration: e.duration,
        timestamp: e.timestamp,
        target: e.target,
      });
    });

    // Log errors
    prisma.$on('error', (e: LogEvent) => {
      logger.error('Prisma error', {
        message: e.message,
        timestamp: e.timestamp,
        target: e.target,
      });
    });

    // Log info
    prisma.$on('info', (e: LogEvent) => {
      logger.info('Prisma info', {
        message: e.message,
        timestamp: e.timestamp,
        target: e.target,
      });
    });

    // Log warnings
    prisma.$on('warn', (e: LogEvent) => {
      logger.warn('Prisma warning', {
        message: e.message,
        timestamp: e.timestamp,
        target: e.target,
      });
    });
  }

  /**
   * Connect to the database
   */
  public static async connect(): Promise<void> {
    try {
      const prisma = PrismaClientManager.getInstance();
      await prisma.client.$connect();
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
      await PrismaClientManager.instance.client.$disconnect();
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
      await prisma.client.$queryRaw`SELECT 1`;

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
