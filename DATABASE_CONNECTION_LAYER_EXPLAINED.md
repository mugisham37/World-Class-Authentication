# Database Connection Layer: Comprehensive Guide

This document provides a detailed explanation of the database connection layer in the World-Class-Authentication system. It covers the architecture, components, interactions, and best practices for working with this robust data access layer.

## Table of Contents

1. [Overview](#overview)
2. [Architecture and Design Principles](#architecture-and-design-principles)
3. [Key Components](#key-components)
   - [Database Manager](#database-manager)
   - [Connection Wrapper](#connection-wrapper)
   - [Query Builder](#query-builder)
   - [PostgreSQL Connection](#postgresql-connection)
   - [Redis Cache](#redis-cache)
   - [Prisma Client](#prisma-client)
   - [Connection Monitor](#connection-monitor)
   - [Metrics Collector](#metrics-collector)
4. [Repository Pattern Implementation](#repository-pattern-implementation)
5. [Error Handling and Resilience](#error-handling-and-resilience)
6. [Performance Optimization](#performance-optimization)
7. [Configuration System](#configuration-system)
8. [Best Practices](#best-practices)

## Overview

The database connection layer provides a robust, high-performance, and type-safe interface for interacting with databases in the application. It abstracts away the complexities of database connections, query building, caching, and error handling, allowing developers to focus on business logic rather than infrastructure concerns.

The layer supports multiple database technologies:

- **PostgreSQL**: For relational data storage
- **Redis**: For caching and pub/sub messaging
- **Prisma**: For type-safe ORM capabilities

## Architecture and Design Principles

The database connection layer is built on several key design principles:

### 1. Intelligent Simplicity

The architecture is sophisticated enough to handle enterprise-scale challenges but simple enough that any developer can understand and extend it. This is achieved through clear abstractions, consistent interfaces, and comprehensive documentation.

### 2. Layered Architecture

The system uses a layered architecture:

```
┌─────────────────────────────────────────────────────────┐
│                   Application Layer                     │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│                   Repository Layer                      │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│                Database Connection Layer                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │ Connection  │  │    Query    │  │    Connection   │  │
│  │  Wrapper    │  │   Builder   │  │     Monitor     │  │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘  │
│         │               │                   │           │
│  ┌──────▼──────┐  ┌─────▼─────┐  ┌─────────▼─────────┐  │
│  │  PostgreSQL │  │   Redis   │  │      Prisma       │  │
│  │ Connection  │  │   Cache   │  │      Client       │  │
│  └─────────────┘  └───────────┘  └───────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### 3. Connection Pooling

The system implements efficient resource orchestration for database connections, maintaining pools of connections to avoid the overhead of establishing new connections for each operation.

### 4. Layered Caching

A multi-level caching strategy is implemented:

- **L1**: In-memory cache for ultra-fast access to frequently used data
- **L2**: Redis cache for distributed caching across multiple application instances
- **L3**: Database for persistent storage

### 5. Type Safety

The system leverages TypeScript's type system to catch errors at compile time, providing interfaces and types for all database operations.

### 6. Observability

Comprehensive metrics, logging, and health monitoring are built into the system, allowing for real-time visibility into database performance and health.

### 7. Resilience

The system implements the circuit breaker pattern, automatic retry logic, and graceful degradation to handle database failures and maintain system stability.

## Key Components

### Database Manager

The `DatabaseManager` class is the central orchestrator for all database connections. It's responsible for:

- **Initialization**: Establishing connections to all database systems at application startup
- **Shutdown**: Gracefully closing connections at application shutdown
- **Health Checks**: Monitoring the health of all database connections

**Key Implementation Details:**

```typescript
// src/data/connections/database-manager.ts
export class DatabaseManager {
  private static isInitialized = false;

  public static async initialize(): Promise<void> {
    // Connect to all database systems
    await connectDatabase(); // Prisma
    await connectPostgres(); // PostgreSQL
    await connectRedis(); // Redis

    // Start monitoring and metrics collection
    metricsCollector.startCollecting();
    connectionMonitor.start();
  }

  public static async shutdown(): Promise<void> {
    // Disconnect from all database systems
    await disconnectDatabase(); // Prisma
    await disconnectPostgres(); // PostgreSQL
    await disconnectRedis(); // Redis

    // Stop monitoring and metrics collection
    metricsCollector.stopCollecting();
    connectionMonitor.stop();
  }

  public static async healthCheck(): Promise<{
    status: string;
    prisma: { status: string; details?: string };
    postgres: { status: string; details?: string };
    redis: { status: string; details?: string };
  }> {
    // Check health of all database systems
    const prismaStatus = await checkPrismaHealth();
    const postgresStatus = await getPostgresStatus();
    const redisStatus = await getRedisStatus();

    // Determine overall status
    const overallStatus =
      prismaStatus.status === 'ok' && postgresStatus.status === 'ok' && redisStatus.status === 'ok'
        ? 'ok'
        : 'error';

    return {
      status: overallStatus,
      prisma: prismaStatus,
      postgres: postgresStatus,
      redis: redisStatus,
    };
  }
}
```

The `DatabaseManager` follows the Singleton pattern to ensure only one instance manages database connections throughout the application lifecycle. It provides convenience methods (`initializeDatabase`, `shutdownDatabase`, `getDatabaseHealth`) for easy access to its functionality.

### Connection Wrapper

The `ConnectionWrapper` class provides a high-level interface for database operations, combining the query builder with transaction management and connection pooling. It's designed to be the primary entry point for database operations in the application.

**Key Features:**

1. **Query Execution**: Methods for executing SQL queries with parameters
2. **Transaction Management**: Support for nested transactions with proper isolation
3. **Retry Logic**: Automatic retry for transient database errors
4. **Metrics Tracking**: Integration with the metrics collector for performance monitoring
5. **Logging**: Comprehensive logging of database operations

**Key Implementation Details:**

```typescript
// src/data/connections/connection-wrapper.ts
export class ConnectionWrapper {
  private static instance: ConnectionWrapper;
  private options: Required<ConnectionWrapperOptions>;
  private queryBuilder: QueryBuilder;
  private transactionClient: any = null;
  private transactionDepth: number = 0;

  // Execute a query with parameters
  public async query<T = any>(text: string, params: any[] = []): Promise<T[]> {
    const start = Date.now();
    let error: any = null;
    let retries = 0;

    while (true) {
      try {
        // Execute query using transaction client or direct connection
        const result = this.transactionClient
          ? await this.transactionClient.query(text, params)
          : await pgQuery(text, params);

        // Log query if enabled
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

        // Retry for transient errors if enabled
        if (
          this.options.enableRetries &&
          retries < this.options.maxRetries &&
          this.isTransientError(err)
        ) {
          retries++;
          const delay = this.options.retryBaseDelay * Math.pow(2, retries - 1);
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }

        // Log error and throw
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
        // Track metrics if enabled
        if (this.options.trackMetrics && (error === null || retries >= this.options.maxRetries)) {
          const duration = Date.now() - start;
          metricsCollector.trackPostgresQuery(duration, !!error, !!this.transactionClient);
        }
      }
    }
  }

  // Execute a transaction
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
}

// Export a singleton instance
export const db = ConnectionWrapper.getInstance();
```

The `ConnectionWrapper` provides specialized query methods like `queryOne`, `queryValue`, `queryCount`, and `queryBoolean` to handle common query patterns more efficiently. It also provides access to the query builder, Redis cache, and metrics collector.

### Query Builder

The `QueryBuilder` class provides a fluent interface for building SQL queries, allowing developers to construct complex queries without writing raw SQL. It supports a wide range of SQL operations and integrates with the caching system for improved performance.

**Key Features:**

1. **Fluent Interface**: Chainable methods for building queries
2. **Type Safety**: TypeScript types for query parameters and results
3. **Caching Integration**: Automatic caching of query results
4. **Metrics Tracking**: Performance monitoring for queries
5. **Pagination Support**: Built-in methods for pagination

**Key Implementation Details:**

```typescript
// src/data/connections/query-builder.ts
export class QueryBuilder {
  private table: string = '';
  private alias: string = '';
  private selectColumns: string[] = [];
  private whereConditions: QueryCondition[] = [];
  private joinClauses: QueryJoin[] = [];
  private groupByColumns: string[] = [];
  private havingConditions: QueryCondition[] = [];
  private orderByClauses: QueryOrder[] = [];
  private limitValue: number | null = null;
  private offsetValue: number | null = null;
  private parameters: any[] = [];
  private cacheKey: string | null = null;
  private cacheTTL: number | null = null;
  private options: Required<QueryBuilderOptions>;

  // Set the table to query
  public from(table: string, alias?: string): QueryBuilder {
    this.table = table;
    this.alias = alias || '';
    return this;
  }

  // Set the columns to select
  public select(...columns: string[]): QueryBuilder {
    this.selectColumns = columns.length > 0 ? columns : ['*'];
    return this;
  }

  // Add a WHERE condition
  public where(column: string, operator: string, value: any): QueryBuilder {
    this.whereConditions.push({ column, operator, value });
    this.parameters.push(value);
    return this;
  }

  // Build the SQL query
  public build(): { sql: string; params: any[] } {
    // Build SELECT clause
    const selectClause = `SELECT ${this.selectColumns.join(', ')}`;

    // Build FROM clause
    const fromClause = `FROM ${this.table}${this.alias ? ` AS ${this.alias}` : ''}`;

    // Build JOIN clauses
    const joinClauses = this.joinClauses
      .map(join => {
        return `${join.type} JOIN ${join.table}${join.alias ? ` AS ${join.alias}` : ''} ON ${join.on}`;
      })
      .join(' ');

    // Build WHERE clause
    let whereClause = '';
    if (this.whereConditions.length > 0) {
      const conditions = this.whereConditions.map((condition, index) => {
        // Handle different condition types
        if (condition.operator === 'RAW') {
          return condition.value;
        }

        if (condition.value === 'NULL' || condition.value === 'NOT NULL') {
          return `${condition.column} ${condition.operator} ${condition.value}`;
        }

        if (
          condition.operator === 'IN' ||
          condition.operator === 'NOT IN' ||
          condition.operator === 'BETWEEN'
        ) {
          return `${condition.column} ${condition.operator} ${condition.value}`;
        }

        return `${condition.column} ${condition.operator} $${this.parameters.indexOf(condition.value) + 1}`;
      });

      whereClause = `WHERE ${conditions.join(' AND ')}`;
    }

    // Build complete SQL query
    const sql = [
      selectClause,
      fromClause,
      joinClauses,
      whereClause,
      // ... other clauses
    ]
      .filter(Boolean)
      .join(' ');

    return { sql, params: this.parameters };
  }

  // Execute the query and return all results
  public async get<T = any>(): Promise<T[]> {
    const { sql, params } = this.build();
    const start = Date.now();
    let error: any = null;
    let isCacheHit = false;

    try {
      // Check cache if enabled
      if (this.options.enableCaching && this.cacheKey) {
        const cachedResult = await redisCache.get<T[]>(this.cacheKey);

        if (cachedResult) {
          isCacheHit = true;
          return cachedResult;
        }
      }

      // Execute query
      const result = await query(sql, params);

      // Cache result if enabled
      if (this.options.enableCaching && this.cacheKey && this.cacheTTL) {
        await redisCache.set(this.cacheKey, result.rows, this.cacheTTL);
      }

      return result.rows;
    } catch (err) {
      error = err;
      throw new DatabaseError(
        `Query execution failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
        'QUERY_EXECUTION_ERROR',
        err instanceof Error ? err : undefined
      );
    } finally {
      // Track metrics
      if (this.options.trackMetrics) {
        const duration = Date.now() - start;
        metricsCollector.trackPostgresQuery(duration, !!error, false);
      }
    }
  }
}
```

The `QueryBuilder` provides specialized execution methods like `first`, `value`, `pluck`, and `keyBy` to handle common query patterns. It also supports CRUD operations with `insert`, `update`, and `delete` methods.

### PostgreSQL Connection

The PostgreSQL connection module provides a connection pool for PostgreSQL database operations. It handles connection establishment, query execution, and transaction management.

**Key Features:**

1. **Connection Pooling**: Efficient management of database connections
2. **Transaction Support**: Methods for executing transactions
3. **Health Monitoring**: Health checks for the PostgreSQL connection
4. **Error Handling**: Robust error handling for database operations

**Key Implementation Details:**

```typescript
// src/data/connections/postgres.ts
class PostgresConnectionPool {
  private static instance: Pool;
  private static isInitialized = false;

  // Get the PostgreSQL connection pool instance
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

  // Connect to PostgreSQL and test the connection
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
}

// Execute a query with parameters
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

// Execute a transaction
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
```

The PostgreSQL connection module provides a singleton pool instance to ensure efficient connection management across the application. It also provides methods for executing queries and transactions.

### Redis Cache

The Redis cache module provides a caching interface with a layered caching strategy. It handles connection management, cache operations, and pub/sub messaging.

**Key Features:**

1. **Layered Caching**: L1 (in-memory) and L2 (Redis) caching
2. **Connection Management**: Efficient management of Redis connections
3. **Circuit Breaker**: Protection against Redis failures
4. **Pub/Sub Messaging**: Support for publish/subscribe messaging
5. **Health Monitoring**: Health checks for the Redis connection

**Key Implementation Details:**

```typescript
// src/data/connections/redis.ts
class RedisConnectionManager {
  private static instance: RedisClientType;
  private static isInitialized = false;
  private static connectionFailures = 0;
  private static circuitOpen = false;
  private static circuitResetTimeout: NodeJS.Timeout | null = null;

  // Get the Redis client instance
  public static getInstance(): RedisClientType {
    if (RedisConnectionManager.circuitOpen) {
      throw new DatabaseError(
        'Redis circuit breaker is open due to multiple connection failures',
        'REDIS_CIRCUIT_OPEN'
      );
    }

    if (!RedisConnectionManager.instance) {
      RedisConnectionManager.instance = createClient(redisConfig);
      RedisConnectionManager.setupEventHandlers();
    }

    return RedisConnectionManager.instance;
  }

  // Handle connection failure and implement circuit breaker pattern
  private static handleConnectionFailure(): void {
    RedisConnectionManager.connectionFailures++;

    if (RedisConnectionManager.connectionFailures >= RedisConnectionManager.CIRCUIT_THRESHOLD) {
      if (!RedisConnectionManager.circuitOpen) {
        logger.warn(
          `Redis circuit breaker opened after ${RedisConnectionManager.connectionFailures} failures`
        );
        RedisConnectionManager.circuitOpen = true;

        // Set timeout to reset circuit breaker
        RedisConnectionManager.circuitResetTimeout = setTimeout(() => {
          logger.info('Redis circuit breaker reset, attempting to reconnect');
          RedisConnectionManager.circuitOpen = false;
          RedisConnectionManager.connectionFailures = 0;
        }, RedisConnectionManager.CIRCUIT_RESET_TIMEOUT);
      }
    }
  }
}

// Redis cache implementation with layered caching
export class RedisCache {
  private static readonly MEMORY_CACHE = new Map<string, { value: any; expiry: number }>();
  private static readonly MEMORY_CACHE_TTL = 60; // 1 minute in seconds

  // Set a value in the cache
  public static async set(key: string, value: any, ttl?: number): Promise<void> {
    const prefixedKey = `${dbConfig.redis?.keyPrefix || ''}${key}`;
    const serializedValue = JSON.stringify(value);

    try {
      const client = RedisConnectionManager.getInstance();

      // Set in Redis (L2 cache)
      if (ttl) {
        await client.set(prefixedKey, serializedValue, { EX: ttl });
      } else {
        await client.set(prefixedKey, serializedValue);
      }

      // Set in memory cache (L1 cache)
      RedisCache.MEMORY_CACHE.set(prefixedKey, {
        value,
        expiry: Date.now() + RedisCache.MEMORY_CACHE_TTL * 1000,
      });
    } catch (error) {
      logger.error('Failed to set cache key', { key: prefixedKey, error });
      throw new DatabaseError(
        'Failed to set cache key',
        'REDIS_CACHE_SET_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  // Get a value from the cache
  public static async get<T = any>(key: string): Promise<T | null> {
    const prefixedKey = `${dbConfig.redis?.keyPrefix || ''}${key}`;

    try {
      // Check memory cache first (L1)
      const memoryCache = RedisCache.MEMORY_CACHE.get(prefixedKey);
      if (memoryCache && memoryCache.expiry > Date.now()) {
        logger.debug('Cache hit (memory)', { key: prefixedKey });
        return memoryCache.value as T;
      }

      // Check Redis (L2)
      const client = RedisConnectionManager.getInstance();
      const value = await client.get(prefixedKey);

      if (value) {
        logger.debug('Cache hit (Redis)', { key: prefixedKey });
        const parsed = JSON.parse(value) as T;

        // Update memory cache
        RedisCache.MEMORY_CACHE.set(prefixedKey, {
          value: parsed,
          expiry: Date.now() + RedisCache.MEMORY_CACHE_TTL * 1000,
        });

        return parsed;
      }

      logger.debug('Cache miss', { key: prefixedKey });
      return null;
    } catch (error) {
      logger.error('Failed to get cache key', { key: prefixedKey, error });
      // Don't throw error on cache miss, just return null
      return null;
    }
  }
}
```

The Redis cache module implements a two-level caching strategy with an in-memory cache for ultra-fast access and a Redis cache for distributed caching. It also implements the circuit breaker pattern to handle Redis failures gracefully.

### Prisma Client

The Prisma client module provides a type-safe ORM interface for database operations. It handles connection management, query execution, and error handling.

**Key Features:**

1. **Type Safety**: TypeScript types for database models and operations
2. **Connection Management**: Efficient management of database connections
3. **Event Logging**: Comprehensive logging of database operations
4. **Health Monitoring**: Health checks for the database connection

**Key Implementation Details:**

```typescript
// src/data/prisma/client.ts
class PrismaClientManager {
  private static instance: PrismaClient;
  private static isInitialized = false;

  // Get the Prisma client instance
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

  // Set up logging for Prisma events
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
  }

  // Connect to the database
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

  // Check the health of the Prisma client
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
```

The Prisma client module provides a singleton client instance to ensure efficient connection management across the application. It also provides methods for connecting to the database and checking the health of the connection.

### Connection Monitor

The `ConnectionMonitor` class monitors the health of all database connections and provides real-time visibility into their status. It periodically checks the health of all connections and emits events when their status changes. It also maintains a history of connection health for trend analysis.

### Metrics Collector

The `MetricsCollector` class collects performance metrics for database operations. It tracks query execution times, cache hit rates, connection pool utilization, and other key metrics. These metrics are used for performance monitoring, optimization, and alerting.

## Repository Pattern Implementation

The database connection layer implements the Repository pattern to provide a clean, domain-focused interface for data access. This pattern abstracts away the details of data storage and retrieval, allowing the application to work with domain objects rather than database entities.

### Base Repository

The `BaseRepository` interface defines the common operations for all repositories:

```typescript
// src/data/repositories/base.repository.ts
export interface BaseRepository<T, ID> {
  findById(id: ID): Promise<T | null>;
  findAll(): Promise<T[]>;
  findMany(filter?: any): Promise<T[]>;
  create(data: any): Promise<T>;
  update(id: ID, data: any): Promise<T>;
  delete(id: ID): Promise<boolean>;
  count(filter?: any): Promise<number>;
  transaction<R>(callback: () => Promise<R>): Promise<R>;
}

export interface TransactionManager {
  withTransaction(tx: any): BaseRepository<any, any>;
}
```

### Prisma Base Repository

The `PrismaBaseRepository` class provides a base implementation of the `BaseRepository` interface using Prisma:

```typescript
// src/data/repositories/prisma-base.repository.ts
export abstract class PrismaBaseRepository<T, ID> implements BaseRepository<T, ID> {
  protected readonly prisma: PrismaClient;
  protected abstract readonly modelName: string;

  constructor(prismaClient?: PrismaClient) {
    this.prisma = prismaClient || prisma;
  }

  async findById(id: ID): Promise<T | null> {
    try {
      const result = await (this.prisma as any)[this.modelName].findUnique({
        where: { id },
      });
      return result as T | null;
    } catch (error) {
      logger.error(`Error finding ${this.modelName} by ID`, { id, error });
      throw new DatabaseError(
        `Error finding ${this.modelName} by ID`,
        `${this.modelName.toUpperCase()}_FIND_BY_ID_ERROR`,
        error instanceof Error ? error : undefined
      );
    }
  }

  // Other methods...
}
```

### User Repository

The `UserRepository` interface extends the `BaseRepository` interface with user-specific operations:

```typescript
// src/data/repositories/user.repository.ts
export interface UserRepository extends BaseRepository<User, string> {
  findByEmail(email: string): Promise<User | null>;
  findByUsername(username: string): Promise<User | null>;
  findWithProfile(id: string): Promise<UserWithProfile | null>;
  findManyWithProfiles(filter?: UserFilterOptions): Promise<UserWithProfile[]>;
  createWithProfile(data: CreateUserData): Promise<UserWithProfile>;
  updateWithProfile(id: string, data: UpdateUserData): Promise<UserWithProfile>;
  updateLastLogin(id: string): Promise<User>;
}
```

The `PrismaUserRepository` class implements the `UserRepository` interface using Prisma:

```typescript
// src/data/repositories/user.repository.ts
```
