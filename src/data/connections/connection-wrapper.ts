import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import { pool, query as pgQuery, transaction as pgTransaction } from './postgres';
import { redisCache } from './redis';
import { createQueryBuilder, QueryBuilder, QueryBuilderOptions } from './query-builder';
import { metricsCollector } from './metrics-collector';

/**
 * Connection wrapper options
 */
export interface ConnectionWrapperOptions {
  /**
   * Query builder options
   */
  queryBuilderOptions?: QueryBuilderOptions;

  /**
   * Whether to log queries
   * @default true
   */
  logQueries?: boolean;

  /**
   * Whether to track query metrics
   * @default true
   */
  trackMetrics?: boolean;

  /**
   * Whether to enable automatic retries for transient errors
   * @default true
   */
  enableRetries?: boolean;

  /**
   * Maximum number of retries for transient errors
   * @default 3
   */
  maxRetries?: number;

  /**
   * Base delay in milliseconds for exponential backoff
   * @default 100
   */
  retryBaseDelay?: number;
}

/**
 * Connection wrapper
 * Provides a high-level interface for database operations
 */
export class ConnectionWrapper {
  private static instance: ConnectionWrapper;
  private options: Required<ConnectionWrapperOptions>;
  private queryBuilder: QueryBuilder;
  private transactionClient: any = null;
  private transactionDepth: number = 0;

  /**
   * Private constructor to enforce singleton pattern
   * @param options Connection wrapper options
   */
  private constructor(options?: ConnectionWrapperOptions) {
    this.options = {
      queryBuilderOptions: options?.queryBuilderOptions ?? {},
      logQueries: options?.logQueries ?? true,
      trackMetrics: options?.trackMetrics ?? true,
      enableRetries: options?.enableRetries ?? true,
      maxRetries: options?.maxRetries ?? 3,
      retryBaseDelay: options?.retryBaseDelay ?? 100,
    };

    this.queryBuilder = createQueryBuilder(this.options.queryBuilderOptions);
  }

  /**
   * Get the connection wrapper instance
   * @param options Connection wrapper options
   * @returns The connection wrapper instance
   */
  public static getInstance(options?: ConnectionWrapperOptions): ConnectionWrapper {
    if (!ConnectionWrapper.instance) {
      ConnectionWrapper.instance = new ConnectionWrapper(options);
    }
    return ConnectionWrapper.instance;
  }

  /**
   * Execute a query with parameters
   * @param text SQL query
   * @param params Query parameters
   * @returns Query result
   */
  public async query<T = any>(text: string, params: any[] = []): Promise<T[]> {
    const start = Date.now();
    let error: any = null;
    let retries = 0;

    while (true) {
      try {
        // Execute query
        const result = this.transactionClient
          ? await this.transactionClient.query(text, params)
          : await pgQuery(text, params);

        // Log query
        if (this.options.logQueries) {
          logger.debug('Query executed', {
            query: text,
            params,
            duration: Date.now() - start,
            rows: result.rowCount,
          });
        }

        return result.rows;
      } catch (err) {
        error = err;

        // Check if error is transient and retries are enabled
        if (
          this.options.enableRetries &&
          retries < this.options.maxRetries &&
          this.isTransientError(err)
        ) {
          retries++;

          // Calculate delay with exponential backoff
          const delay = this.options.retryBaseDelay * Math.pow(2, retries - 1);

          // Log retry attempt
          logger.warn(
            `Retrying query after transient error (attempt ${retries}/${this.options.maxRetries})`,
            {
              query: text,
              params,
              error: err,
              delay,
            }
          );

          // Wait before retrying
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }

        // Log error
        logger.error('Query execution failed', {
          query: text,
          params,
          error: err,
        });

        throw new DatabaseError(
          `Query execution failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
          'QUERY_EXECUTION_ERROR',
          err instanceof Error ? err : undefined
        );
      } finally {
        // Track metrics if not retrying
        if (this.options.trackMetrics && (error === null || retries >= this.options.maxRetries)) {
          const duration = Date.now() - start;
          metricsCollector.trackPostgresQuery(duration, !!error, !!this.transactionClient);
        }
      }
    }
  }

  /**
   * Execute a query that returns a single row
   * @param text SQL query
   * @param params Query parameters
   * @returns Single row or null if not found
   */
  public async queryOne<T = any>(text: string, params: any[] = []): Promise<T | null> {
    const rows = await this.query<T>(text, params);
    if (rows.length === 0) {
      return null;
    }
    return rows[0] as T;
  }

  /**
   * Execute a query that returns a single value
   * @param text SQL query
   * @param params Query parameters
   * @returns Single value or null if not found
   */
  public async queryValue<T = any>(text: string, params: any[] = []): Promise<T | null> {
    const row = await this.queryOne<Record<string, T>>(text, params);
    if (row === null) {
      return null;
    }

    // Get the first column value
    const columns = Object.keys(row);
    if (columns.length === 0) {
      return null;
    }

    const firstColumn = columns[0];
    // Use a type-safe approach to access the property
    return row[firstColumn as keyof typeof row] as T;
  }

  /**
   * Execute a query that returns a count
   * @param text SQL query
   * @param params Query parameters
   * @returns Count value
   */
  public async queryCount(text: string, params: any[] = []): Promise<number> {
    const value = await this.queryValue<string>(text, params);
    return value !== null ? parseInt(value, 10) : 0;
  }

  /**
   * Execute a query that returns a boolean
   * @param text SQL query
   * @param params Query parameters
   * @returns Boolean value
   */
  public async queryBoolean(text: string, params: any[] = []): Promise<boolean> {
    const value = await this.queryValue<boolean>(text, params);
    return value === true;
  }

  /**
   * Execute a query that returns an array of values from a single column
   * @param text SQL query
   * @param params Query parameters
   * @param columnName Column name (optional, defaults to first column)
   * @returns Array of values
   */
  public async queryColumn<T = any>(
    text: string,
    params: any[] = [],
    columnName?: string
  ): Promise<T[]> {
    const rows = await this.query<Record<string, T>>(text, params);

    if (rows.length === 0) {
      return [];
    }

    // If column is not specified, use the first column
    const firstRow = rows[0];
    if (!firstRow) {
      return [];
    }

    // Ensure we have a valid column name
    const actualColumnName: string = columnName || Object.keys(firstRow)[0] || '';
    if (!actualColumnName) {
      return [];
    }

    const result: T[] = [];

    for (const row of rows) {
      if (row && Object.prototype.hasOwnProperty.call(row, actualColumnName)) {
        // Use a type-safe approach to access the property
        result.push(row[actualColumnName as keyof typeof row] as T);
      } else {
        result.push(null as unknown as T);
      }
    }

    return result;
  }

  /**
   * Execute a transaction
   * @param callback Function to execute within the transaction
   * @returns Result of the callback function
   */
  public async transaction<T>(callback: () => Promise<T>): Promise<T> {
    // If already in a transaction, just execute the callback
    if (this.transactionClient) {
      this.transactionDepth++;
      try {
        const result = await callback();
        this.transactionDepth--;
        return result;
      } catch (error) {
        this.transactionDepth--;
        throw error;
      }
    }

    // Start a new transaction
    return await pgTransaction(async client => {
      this.transactionClient = client;
      this.transactionDepth = 1;

      try {
        const result = await callback();
        this.transactionClient = null;
        this.transactionDepth = 0;
        return result;
      } catch (error) {
        this.transactionClient = null;
        this.transactionDepth = 0;
        throw error;
      }
    });
  }

  /**
   * Execute a function within a transaction
   * @param callback Function to execute within the transaction
   * @returns Result of the callback function
   */
  public async withTransaction<T>(callback: () => Promise<T>): Promise<T> {
    return this.transaction(callback);
  }

  /**
   * Check if currently in a transaction
   * @returns True if in a transaction, false otherwise
   */
  public isInTransaction(): boolean {
    return this.transactionDepth > 0;
  }

  /**
   * Get the current transaction depth
   * @returns Transaction depth (0 if not in a transaction)
   */
  public getTransactionDepth(): number {
    return this.transactionDepth;
  }

  /**
   * Get a query builder instance
   * @returns Query builder instance
   */
  public getQueryBuilder(): QueryBuilder {
    return this.queryBuilder;
  }

  /**
   * Get the Redis cache instance
   * @returns Redis cache instance
   */
  public getCache(): typeof redisCache {
    return redisCache;
  }

  /**
   * Get the PostgreSQL pool
   * @returns PostgreSQL pool
   */
  public getPool(): typeof pool {
    return pool;
  }

  /**
   * Get the metrics collector
   * @returns Metrics collector
   */
  public getMetricsCollector(): typeof metricsCollector {
    return metricsCollector;
  }

  /**
   * Check if an error is transient
   * @param error Error to check
   * @returns True if the error is transient, false otherwise
   */
  private isTransientError(error: any): boolean {
    if (!error) {
      return false;
    }

    // Check for common transient error codes
    const transientCodes = [
      '08000', // connection_exception
      '08003', // connection_does_not_exist
      '08006', // connection_failure
      '08001', // sqlclient_unable_to_establish_sqlconnection
      '08004', // sqlserver_rejected_establishment_of_sqlconnection
      '08007', // transaction_resolution_unknown
      '40001', // serialization_failure
      '40P01', // deadlock_detected
      '57P01', // admin_shutdown
      '57P02', // crash_shutdown
      '57P03', // cannot_connect_now
      '53300', // too_many_connections
    ];

    // Check for specific error codes
    if (error.code && transientCodes.includes(error.code)) {
      return true;
    }

    // Check for connection-related errors
    if (error.message) {
      const message = error.message.toLowerCase();
      return (
        message.includes('connection') ||
        message.includes('timeout') ||
        message.includes('deadlock') ||
        message.includes('serialization') ||
        message.includes('too many clients') ||
        message.includes('terminating connection')
      );
    }

    return false;
  }
}

// Export a singleton instance
export const db = ConnectionWrapper.getInstance();
