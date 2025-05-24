import { Pool, type PoolClient } from 'pg';
import { dbConfig } from '../../config/database-config';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';

/**
 * PostgreSQL connection pool configuration
 */
const poolConfig = {
  host: dbConfig.postgres.host,
  port: dbConfig.postgres.port,
  user: dbConfig.postgres.username,
  password: dbConfig.postgres.password,
  database: dbConfig.postgres.database,
  ssl: dbConfig.postgres.ssl,
  max: dbConfig.postgres.poolSize,
  idleTimeoutMillis: dbConfig.postgres.idleTimeoutMillis,
  connectionTimeoutMillis: dbConfig.postgres.connectionTimeoutMillis,
};

/**
 * PostgreSQL connection pool singleton
 */
class PostgresConnectionPool {
  private static instance: Pool;
  private static isInitialized = false;

  /**
   * Get the PostgreSQL connection pool instance
   * Creates a new instance if one doesn't exist
   */
  public static getInstance(): Pool {
    if (!PostgresConnectionPool.instance) {
      PostgresConnectionPool.instance = new Pool(poolConfig);

      // Set up error handler for the pool
      PostgresConnectionPool.instance.on('error', (err: Error) => {
        logger.error('Unexpected error on idle PostgreSQL client', { error: err });
      });

      PostgresConnectionPool.isInitialized = true;
    }
    return PostgresConnectionPool.instance;
  }

  /**
   * Connect to PostgreSQL and test the connection
   */
  public static async connect(): Promise<void> {
    try {
      const pool = PostgresConnectionPool.getInstance();
      const client = await pool.connect();
      client.release();
      logger.info('PostgreSQL connection established successfully');
    } catch (error) {
      logger.error('Failed to connect to PostgreSQL', { error });
      throw new DatabaseError(
        'Failed to connect to PostgreSQL',
        'POSTGRES_CONNECTION_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Close all connections in the pool
   */
  public static async disconnect(): Promise<void> {
    if (!PostgresConnectionPool.isInitialized || !PostgresConnectionPool.instance) {
      return;
    }

    try {
      await PostgresConnectionPool.instance.end();
      PostgresConnectionPool.isInitialized = false;
      logger.info('PostgreSQL connection pool closed');
    } catch (error) {
      logger.error('Error closing PostgreSQL connection pool', { error });
      throw new DatabaseError(
        'Error closing PostgreSQL connection pool',
        'POSTGRES_DISCONNECT_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Get a client from the pool
   * @returns PostgreSQL client
   */
  public static async getClient(): Promise<PoolClient> {
    try {
      const pool = PostgresConnectionPool.getInstance();
      return await pool.connect();
    } catch (error) {
      logger.error('Failed to get PostgreSQL client', { error });
      throw new DatabaseError(
        'Failed to get PostgreSQL client',
        'POSTGRES_CLIENT_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check PostgreSQL connection status
   * @returns Connection status
   */
  public static async healthCheck(): Promise<{ status: string; details?: string }> {
    try {
      const pool = PostgresConnectionPool.getInstance();
      const client = await pool.connect();
      const result = await client.query('SELECT NOW()');
      client.release();

      return {
        status: 'ok',
        details: `Connected to PostgreSQL at ${dbConfig.postgres.host}:${dbConfig.postgres.port}`,
      };
    } catch (error) {
      logger.error('PostgreSQL health check failed', { error });
      return {
        status: 'error',
        details: `Failed to connect to PostgreSQL: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }
}

/**
 * Execute a query with parameters
 * @param text SQL query
 * @param params Query parameters
 * @returns Query result
 */
export async function query<T = any>(text: string, params: any[] = []): Promise<T> {
  const client = await PostgresConnectionPool.getClient();
  try {
    const start = Date.now();
    const result = await client.query(text, params);
    const duration = Date.now() - start;

    logger.debug('Executed query', {
      query: text,
      duration,
      rows: result.rowCount,
    });

    return result.rows as T;
  } catch (error) {
    logger.error('Query execution failed', {
      query: text,
      params,
      error,
    });
    throw new DatabaseError(
      'Query execution failed',
      'POSTGRES_QUERY_ERROR',
      error instanceof Error ? error : undefined
    );
  } finally {
    client.release();
  }
}

/**
 * Execute a transaction
 * @param callback Function to execute within the transaction
 * @returns Result of the callback function
 */
export async function transaction<T>(callback: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await PostgresConnectionPool.getClient();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    logger.error('Transaction failed', { error });
    throw new DatabaseError(
      'Transaction failed',
      'POSTGRES_TRANSACTION_ERROR',
      error instanceof Error ? error : undefined
    );
  } finally {
    client.release();
  }
}

// Export the pool for direct access if needed
export const pool = PostgresConnectionPool.getInstance();

// Export connection methods
export const connectPostgres = PostgresConnectionPool.connect;
export const disconnectPostgres = PostgresConnectionPool.disconnect;
export const getPostgresStatus = PostgresConnectionPool.healthCheck;
