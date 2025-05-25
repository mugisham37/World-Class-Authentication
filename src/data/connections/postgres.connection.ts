import { PrismaClient } from '@prisma/client';
import { Pool, PoolClient } from 'pg';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import { databaseConfig } from '../../config/database-config';
import { MetricsCollector } from './metrics-collector';

/**
 * PostgreSQL connection options interface
 */
export interface PostgresConnectionOptions {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  ssl?: boolean;
  maxPoolSize?: number;
  idleTimeoutMillis?: number;
  connectionTimeoutMillis?: number;
}

/**
 * PostgreSQL connection manager
 * Manages connections to PostgreSQL database
 */
export class PostgresConnection {
  private static instance: PostgresConnection;
  private pool: Pool;
  private prismaClient: PrismaClient;
  private metricsCollector: MetricsCollector;
  private isConnected: boolean = false;
  private connectionAttempts: number = 0;
  private readonly maxConnectionAttempts: number = 5;

  /**
   * Private constructor to enforce singleton pattern
   * @param options Connection options
   */
  private constructor(options: PostgresConnectionOptions) {
    this.pool = new Pool({
      host: options.host,
      port: options.port,
      database: options.database,
      user: options.user,
      password: options.password,
      ssl: options.ssl,
      max: options.maxPoolSize || databaseConfig.postgres.poolSize,
      idleTimeoutMillis: options.idleTimeoutMillis || databaseConfig.postgres.idleTimeout,
      connectionTimeoutMillis:
        options.connectionTimeoutMillis || databaseConfig.postgres.connectionTimeout,
    });

    this.prismaClient = new PrismaClient({
      datasources: {
        db: {
          url: `postgresql://${options.user}:${options.password}@${options.host}:${options.port}/${options.database}${
            options.ssl ? '?sslmode=require' : ''
          }`,
        },
      },
      log: databaseConfig.prisma.logLevel,
    });

    this.metricsCollector = MetricsCollector.getInstance();

    // Set up event listeners
    this.setupEventListeners();
  }

  /**
   * Get the singleton instance
   * @param options Connection options
   * @returns The singleton instance
   */
  public static getInstance(options?: PostgresConnectionOptions): PostgresConnection {
    if (!PostgresConnection.instance) {
      if (!options) {
        throw new Error('PostgreSQL connection options are required for initial setup');
      }
      PostgresConnection.instance = new PostgresConnection(options);
    }
    return PostgresConnection.instance;
  }

  /**
   * Set up event listeners for the connection pool
   */
  private setupEventListeners(): void {
    this.pool.on('connect', (client: PoolClient) => {
      this.isConnected = true;
      this.connectionAttempts = 0;
      logger.info('New client connected to PostgreSQL pool');
      this.metricsCollector.incrementCounter('postgres_connections_total');
    });

    this.pool.on('error', (err: Error, client: PoolClient) => {
      logger.error('Unexpected error on idle PostgreSQL client', { error: err });
      this.metricsCollector.incrementCounter('postgres_connection_errors_total');
    });

    this.pool.on('remove', (client: PoolClient) => {
      logger.debug('Client removed from PostgreSQL pool');
      this.metricsCollector.decrementGauge('postgres_active_connections');
    });
  }

  /**
   * Initialize the connection
   * @returns Promise that resolves when the connection is established
   */
  public async initialize(): Promise<void> {
    try {
      // Test the connection
      const client = await this.pool.connect();
      client.release();

      // Connect Prisma
      await this.prismaClient.$connect();

      this.isConnected = true;
      logger.info('Successfully connected to PostgreSQL database');
      this.metricsCollector.incrementCounter('postgres_connection_successes_total');
    } catch (error) {
      this.connectionAttempts++;
      this.isConnected = false;
      logger.error('Failed to connect to PostgreSQL database', {
        error,
        attempt: this.connectionAttempts,
      });
      this.metricsCollector.incrementCounter('postgres_connection_failures_total');

      if (this.connectionAttempts < this.maxConnectionAttempts) {
        const backoffTime = Math.pow(2, this.connectionAttempts) * 1000; // Exponential backoff
        logger.info(`Retrying connection in ${backoffTime}ms...`);
        await new Promise(resolve => setTimeout(resolve, backoffTime));
        return this.initialize();
      }

      throw new DatabaseError(
        'Failed to connect to PostgreSQL database after multiple attempts',
        'POSTGRES_CONNECTION_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Get a client from the pool
   * @returns Promise that resolves to a client
   */
  public async getClient(): Promise<PoolClient> {
    if (!this.isConnected) {
      await this.initialize();
    }

    try {
      const startTime = Date.now();
      const client = await this.pool.connect();
      const duration = Date.now() - startTime;

      this.metricsCollector.observeHistogram('postgres_connection_duration_ms', duration);
      this.metricsCollector.incrementGauge('postgres_active_connections');

      return client;
    } catch (error) {
      logger.error('Error getting PostgreSQL client from pool', { error });
      this.metricsCollector.incrementCounter('postgres_client_acquisition_errors_total');
      throw new DatabaseError(
        'Error getting PostgreSQL client from pool',
        'POSTGRES_CLIENT_ACQUISITION_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Execute a query
   * @param text The query text
   * @param params The query parameters
   * @returns Promise that resolves to the query result
   */
  public async query(text: string, params: any[] = []): Promise<any> {
    const client = await this.getClient();
    const startTime = Date.now();

    try {
      const result = await client.query(text, params);
      const duration = Date.now() - startTime;

      this.metricsCollector.observeHistogram('postgres_query_duration_ms', duration);
      this.metricsCollector.incrementCounter('postgres_queries_total');

      if (duration > databaseConfig.postgres.slowQueryThreshold) {
        logger.warn('Slow query detected', {
          query: text,
          duration,
          threshold: databaseConfig.postgres.slowQueryThreshold,
        });
        this.metricsCollector.incrementCounter('postgres_slow_queries_total');
      }

      return result;
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error('Error executing PostgreSQL query', { error, query: text });
      this.metricsCollector.incrementCounter('postgres_query_errors_total');
      throw new DatabaseError(
        'Error executing PostgreSQL query',
        'POSTGRES_QUERY_ERROR',
        error instanceof Error ? error : undefined
      );
    } finally {
      client.release();
    }
  }

  /**
   * Execute a transaction
   * @param callback The transaction callback
   * @returns Promise that resolves to the transaction result
   */
  public async transaction<T>(callback: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.getClient();
    const startTime = Date.now();

    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');

      const duration = Date.now() - startTime;
      this.metricsCollector.observeHistogram('postgres_transaction_duration_ms', duration);
      this.metricsCollector.incrementCounter('postgres_transactions_total');

      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      const duration = Date.now() - startTime;
      logger.error('Error executing PostgreSQL transaction', { error, duration });
      this.metricsCollector.incrementCounter('postgres_transaction_errors_total');
      throw new DatabaseError(
        'Error executing PostgreSQL transaction',
        'POSTGRES_TRANSACTION_ERROR',
        error instanceof Error ? error : undefined
      );
    } finally {
      client.release();
    }
  }

  /**
   * Get the Prisma client
   * @returns The Prisma client
   */
  public getPrismaClient(): PrismaClient {
    if (!this.isConnected) {
      throw new Error('Cannot get Prisma client before connection is initialized');
    }
    return this.prismaClient;
  }

  /**
   * Check if the connection is healthy
   * @returns Promise that resolves to true if the connection is healthy
   */
  public async healthCheck(): Promise<boolean> {
    try {
      await this.query('SELECT 1');
      return true;
    } catch (error) {
      logger.error('PostgreSQL health check failed', { error });
      return false;
    }
  }

  /**
   * Close the connection
   * @returns Promise that resolves when the connection is closed
   */
  public async close(): Promise<void> {
    try {
      await this.prismaClient.$disconnect();
      await this.pool.end();
      this.isConnected = false;
      logger.info('PostgreSQL connection closed');
    } catch (error) {
      logger.error('Error closing PostgreSQL connection', { error });
      throw new DatabaseError(
        'Error closing PostgreSQL connection',
        'POSTGRES_CLOSE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }
}

// Export a function to get the singleton instance
export const getPostgresConnection = (options?: PostgresConnectionOptions): PostgresConnection => {
  return PostgresConnection.getInstance(options);
};
