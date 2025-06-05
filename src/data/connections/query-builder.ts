import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import { query } from './postgres';
import { redisCache } from './redis';
import { metricsCollector } from './metrics-collector';

/**
 * Query builder options
 */
export interface QueryBuilderOptions {
  /**
   * Whether to enable query caching
   * @default true
   */
  enableCaching?: boolean;

  /**
   * Default cache TTL in seconds
   * @default 300 (5 minutes)
   */
  defaultCacheTTL?: number;

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
}

/**
 * Query condition
 */
export interface QueryCondition {
  column: string;
  operator: string;
  value: any;
}

/**
 * Query join
 */
export interface QueryJoin {
  type: 'INNER' | 'LEFT' | 'RIGHT' | 'FULL';
  table: string;
  alias?: string | undefined;
  on: string;
}

/**
 * Query order
 */
export interface QueryOrder {
  column: string;
  direction: 'ASC' | 'DESC';
}

/**
 * Query builder
 * Provides a fluent interface for building SQL queries
 */
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

  /**
   * Create a new query builder
   * @param options Query builder options
   */
  constructor(options?: QueryBuilderOptions) {
    this.options = {
      enableCaching: options?.enableCaching ?? true,
      defaultCacheTTL: options?.defaultCacheTTL ?? 300,
      logQueries: options?.logQueries ?? true,
      trackMetrics: options?.trackMetrics ?? true,
    };
  }

  /**
   * Set the table to query
   * @param table Table name
   * @param alias Table alias (optional)
   * @returns Query builder instance
   */
  public from(table: string, alias?: string): QueryBuilder {
    this.table = table;
    this.alias = alias || '';
    return this;
  }

  /**
   * Set the columns to select
   * @param columns Columns to select
   * @returns Query builder instance
   */
  public select(...columns: string[]): QueryBuilder {
    this.selectColumns = columns.length > 0 ? columns : ['*'];
    return this;
  }

  /**
   * Add a WHERE condition
   * @param column Column name
   * @param operator Operator (=, >, <, etc.)
   * @param value Value
   * @returns Query builder instance
   */
  public where(column: string, operator: string, value: any): QueryBuilder {
    this.whereConditions.push({ column, operator, value });
    this.parameters.push(value);
    return this;
  }

  /**
   * Add a WHERE condition with equals operator
   * @param column Column name
   * @param value Value
   * @returns Query builder instance
   */
  public whereEquals(column: string, value: any): QueryBuilder {
    return this.where(column, '=', value);
  }

  /**
   * Add a WHERE IN condition
   * @param column Column name
   * @param values Array of values
   * @returns Query builder instance
   */
  public whereIn(column: string, values: any[]): QueryBuilder {
    if (values.length === 0) {
      return this.where('1', '=', '0'); // Always false
    }

    const placeholders = values
      .map((_, index) => `$${this.parameters.length + index + 1}`)
      .join(', ');
    this.whereConditions.push({
      column,
      operator: 'IN',
      value: `(${placeholders})`,
    });

    this.parameters.push(...values);
    return this;
  }

  /**
   * Add a WHERE NOT IN condition
   * @param column Column name
   * @param values Array of values
   * @returns Query builder instance
   */
  public whereNotIn(column: string, values: any[]): QueryBuilder {
    if (values.length === 0) {
      return this; // No effect
    }

    const placeholders = values
      .map((_, index) => `$${this.parameters.length + index + 1}`)
      .join(', ');
    this.whereConditions.push({
      column,
      operator: 'NOT IN',
      value: `(${placeholders})`,
    });

    this.parameters.push(...values);
    return this;
  }

  /**
   * Add a WHERE NULL condition
   * @param column Column name
   * @returns Query builder instance
   */
  public whereNull(column: string): QueryBuilder {
    this.whereConditions.push({
      column,
      operator: 'IS',
      value: 'NULL',
    });
    return this;
  }

  /**
   * Add a WHERE NOT NULL condition
   * @param column Column name
   * @returns Query builder instance
   */
  public whereNotNull(column: string): QueryBuilder {
    this.whereConditions.push({
      column,
      operator: 'IS NOT',
      value: 'NULL',
    });
    return this;
  }

  /**
   * Add a WHERE BETWEEN condition
   * @param column Column name
   * @param min Minimum value
   * @param max Maximum value
   * @returns Query builder instance
   */
  public whereBetween(column: string, min: any, max: any): QueryBuilder {
    this.whereConditions.push({
      column,
      operator: 'BETWEEN',
      value: `$${this.parameters.length + 1} AND $${this.parameters.length + 2}`,
    });

    this.parameters.push(min, max);
    return this;
  }

  /**
   * Add a WHERE condition with custom SQL
   * @param sql SQL condition
   * @param params Parameters for the condition
   * @returns Query builder instance
   */
  public whereRaw(sql: string, params: any[] = []): QueryBuilder {
    this.whereConditions.push({
      column: '',
      operator: 'RAW',
      value: sql,
    });

    this.parameters.push(...params);
    return this;
  }

  /**
   * Add a JOIN clause
   * @param type Join type (INNER, LEFT, RIGHT, FULL)
   * @param table Table to join
   * @param on Join condition
   * @param alias Table alias (optional)
   * @returns Query builder instance
   */
  public join(
    type: 'INNER' | 'LEFT' | 'RIGHT' | 'FULL',
    table: string,
    on: string,
    alias?: string
  ): QueryBuilder {
    this.joinClauses.push({
      type,
      table,
      on,
      alias,
    });
    return this;
  }

  /**
   * Add an INNER JOIN clause
   * @param table Table to join
   * @param on Join condition
   * @param alias Table alias (optional)
   * @returns Query builder instance
   */
  public innerJoin(table: string, on: string, alias?: string): QueryBuilder {
    return this.join('INNER', table, on, alias);
  }

  /**
   * Add a LEFT JOIN clause
   * @param table Table to join
   * @param on Join condition
   * @param alias Table alias (optional)
   * @returns Query builder instance
   */
  public leftJoin(table: string, on: string, alias?: string): QueryBuilder {
    return this.join('LEFT', table, on, alias);
  }

  /**
   * Add a RIGHT JOIN clause
   * @param table Table to join
   * @param on Join condition
   * @param alias Table alias (optional)
   * @returns Query builder instance
   */
  public rightJoin(table: string, on: string, alias?: string): QueryBuilder {
    return this.join('RIGHT', table, on, alias);
  }

  /**
   * Add a GROUP BY clause
   * @param columns Columns to group by
   * @returns Query builder instance
   */
  public groupBy(...columns: string[]): QueryBuilder {
    this.groupByColumns.push(...columns);
    return this;
  }

  /**
   * Add a HAVING condition
   * @param column Column name
   * @param operator Operator (=, >, <, etc.)
   * @param value Value
   * @returns Query builder instance
   */
  public having(column: string, operator: string, value: any): QueryBuilder {
    this.havingConditions.push({ column, operator, value });
    this.parameters.push(value);
    return this;
  }

  /**
   * Add an ORDER BY clause
   * @param column Column to order by
   * @param direction Sort direction (ASC or DESC)
   * @returns Query builder instance
   */
  public orderBy(column: string, direction: 'ASC' | 'DESC' = 'ASC'): QueryBuilder {
    this.orderByClauses.push({ column, direction });
    return this;
  }

  /**
   * Set the LIMIT clause
   * @param limit Maximum number of rows to return
   * @returns Query builder instance
   */
  public limit(limit: number): QueryBuilder {
    this.limitValue = limit;
    return this;
  }

  /**
   * Set the OFFSET clause
   * @param offset Number of rows to skip
   * @returns Query builder instance
   */
  public offset(offset: number): QueryBuilder {
    this.offsetValue = offset;
    return this;
  }

  /**
   * Set pagination
   * @param page Page number (1-based)
   * @param pageSize Number of rows per page
   * @returns Query builder instance
   */
  public paginate(page: number, pageSize: number): QueryBuilder {
    const offset = (Math.max(1, page) - 1) * pageSize;
    return this.limit(pageSize).offset(offset);
  }

  /**
   * Set cache key and TTL
   * @param key Cache key
   * @param ttl Time to live in seconds (optional)
   * @returns Query builder instance
   */
  public cache(key: string, ttl?: number): QueryBuilder {
    this.cacheKey = key;
    this.cacheTTL = ttl || this.options.defaultCacheTTL;
    return this;
  }

  /**
   * Build the SQL query
   * @returns SQL query string and parameters
   */
  public build(): { sql: string; params: any[] } {
    if (!this.table) {
      throw new DatabaseError('No table specified', 'QUERY_BUILDER_ERROR');
    }

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
      const conditions = this.whereConditions.map(condition => {
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

    // Build GROUP BY clause
    let groupByClause = '';
    if (this.groupByColumns.length > 0) {
      groupByClause = `GROUP BY ${this.groupByColumns.join(', ')}`;
    }

    // Build HAVING clause
    let havingClause = '';
    if (this.havingConditions.length > 0) {
      const conditions = this.havingConditions.map(condition => {
        return `${condition.column} ${condition.operator} $${this.parameters.indexOf(condition.value) + 1}`;
      });

      havingClause = `HAVING ${conditions.join(' AND ')}`;
    }

    // Build ORDER BY clause
    let orderByClause = '';
    if (this.orderByClauses.length > 0) {
      const orders = this.orderByClauses.map(order => {
        return `${order.column} ${order.direction}`;
      });

      orderByClause = `ORDER BY ${orders.join(', ')}`;
    }

    // Build LIMIT clause
    let limitClause = '';
    if (this.limitValue !== null) {
      limitClause = `LIMIT ${this.limitValue}`;
    }

    // Build OFFSET clause
    let offsetClause = '';
    if (this.offsetValue !== null) {
      offsetClause = `OFFSET ${this.offsetValue}`;
    }

    // Build complete SQL query
    const sql = [
      selectClause,
      fromClause,
      joinClauses,
      whereClause,
      groupByClause,
      havingClause,
      orderByClause,
      limitClause,
      offsetClause,
    ]
      .filter(Boolean)
      .join(' ');

    return { sql, params: this.parameters };
  }

  /**
   * Execute the query and return all results
   * @returns Query result
   */
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

          // Log cache hit
          if (this.options.logQueries) {
            logger.debug('Query cache hit', {
              cacheKey: this.cacheKey,
              sql,
            });
          }

          // Track metrics
          if (this.options.trackMetrics) {
            metricsCollector.trackRedisOperation(0, false, true);
          }

          return cachedResult;
        }
      }

      // Execute query
      const result = await query(sql, params);

      // Cache result if enabled
      if (this.options.enableCaching && this.cacheKey && this.cacheTTL) {
        await redisCache.set(this.cacheKey, result.rows, this.cacheTTL);
      }

      // Log query
      if (this.options.logQueries) {
        logger.debug('Query executed', {
          sql,
          params,
          duration: Date.now() - start,
          rows: result.rowCount,
        });
      }

      return result.rows;
    } catch (err) {
      error = err;

      // Log error
      logger.error('Query execution failed', {
        sql,
        params,
        error: err,
      });

      throw new DatabaseError(
        `Query execution failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
        'QUERY_EXECUTION_ERROR',
        err instanceof Error ? err : undefined
      );
    } finally {
      // Track metrics
      if (this.options.trackMetrics) {
        const duration = Date.now() - start;

        if (!isCacheHit) {
          metricsCollector.trackPostgresQuery(duration, !!error, false);
        }
      }
    }
  }

  /**
   * Execute the query and return the first result
   * @returns First result or null if not found
   */
  public async first<T = any>(): Promise<T | null> {
    const results = await this.limit(1).get<T>();
    return results.length > 0 ? (results[0] as T) : null;
  }

  /**
   * Execute the query and return a single value
   * @param column Column to return
   * @returns Column value or null if not found
   */
  public async value<T = any>(column: string): Promise<T | null> {
    const result = await this.select(column).first<Record<string, T>>();
    return result ? (result[column] as T) : null;
  }

  /**
   * Execute the query and return an array of values from a single column
   * @param column Column to return
   * @returns Array of column values
   */
  public async pluck<T = any>(column: string): Promise<T[]> {
    const results = await this.select(column).get<Record<string, T>>();
    return results.map(result => result[column] as T);
  }

  /**
   * Execute the query and return a key-value object
   * @param keyColumn Column to use as keys
   * @param valueColumn Column to use as values
   * @returns Key-value object
   */
  public async keyBy<K extends string | number, V = any>(
    keyColumn: string,
    valueColumn: string
  ): Promise<Record<K, V>> {
    const results = await this.select(keyColumn, valueColumn).get<Record<string, any>>();

    const output: Record<K, V> = {} as Record<K, V>;
    for (const result of results) {
      const key = result[keyColumn] as K;
      output[key] = result[valueColumn] as V;
    }
    return output;
  }

  /**
   * Execute the query and return the number of rows
   * @returns Number of rows
   */
  public async count(): Promise<number> {
    const result = await this.select('COUNT(*) as count').first<{ count: string }>();
    return result ? parseInt(result.count, 10) : 0;
  }

  /**
   * Execute the query and check if any rows exist
   * @returns True if any rows exist, false otherwise
   */
  public async exists(): Promise<boolean> {
    const count = await this.count();
    return count > 0;
  }

  /**
   * Execute an INSERT query
   * @param data Data to insert
   * @returns Inserted row
   */
  public async insert<T = any>(data: Record<string, any>): Promise<T> {
    const columns = Object.keys(data);
    const values = Object.values(data);
    const placeholders = values.map((_, index) => `$${index + 1}`).join(', ');

    const sql = `INSERT INTO ${this.table} (${columns.join(', ')}) VALUES (${placeholders}) RETURNING *`;

    const start = Date.now();
    let error: any = null;

    try {
      // Execute query
      const result = await query(sql, values);

      // Log query
      if (this.options.logQueries) {
        logger.debug('Insert query executed', {
          sql,
          values,
          duration: Date.now() - start,
        });
      }

      // Invalidate cache if needed
      if (this.options.enableCaching && this.cacheKey) {
        await redisCache.delete(this.cacheKey);
      }

      return result.rows[0];
    } catch (err) {
      error = err;

      // Log error
      logger.error('Insert query failed', {
        sql,
        values,
        error: err,
      });

      throw new DatabaseError(
        `Insert query failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
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

  /**
   * Execute an UPDATE query
   * @param data Data to update
   * @returns Number of affected rows
   */
  public async update(data: Record<string, any>): Promise<number> {
    if (!this.whereConditions.length) {
      throw new DatabaseError('Update query must have WHERE conditions', 'QUERY_BUILDER_ERROR');
    }

    const { sql: whereSQL } = this.build();
    const wherePart = whereSQL.split('WHERE')[1];

    const columns = Object.keys(data);
    const values = Object.values(data);

    const setClauses = columns
      .map((column, index) => {
        return `${column} = $${index + 1}`;
      })
      .join(', ');

    const sql = `UPDATE ${this.table} SET ${setClauses} WHERE ${wherePart} RETURNING *`;

    const start = Date.now();
    let error: any = null;

    try {
      // Execute query
      const result = await query(sql, [...values, ...this.parameters]);

      // Log query
      if (this.options.logQueries) {
        logger.debug('Update query executed', {
          sql,
          values: [...values, ...this.parameters],
          duration: Date.now() - start,
          rows: result.rowCount,
        });
      }

      // Invalidate cache if needed
      if (this.options.enableCaching && this.cacheKey) {
        await redisCache.delete(this.cacheKey);
      }

      return result.rowCount;
    } catch (err) {
      error = err;

      // Log error
      logger.error('Update query failed', {
        sql,
        values: [...values, ...this.parameters],
        error: err,
      });

      throw new DatabaseError(
        `Update query failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
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

  /**
   * Execute a DELETE query
   * @returns Number of affected rows
   */
  public async delete(): Promise<number> {
    if (!this.whereConditions.length) {
      throw new DatabaseError('Delete query must have WHERE conditions', 'QUERY_BUILDER_ERROR');
    }

    const { sql: whereSQL } = this.build();
    const wherePart = whereSQL.split('WHERE')[1];

    const sql = `DELETE FROM ${this.table} WHERE ${wherePart} RETURNING *`;

    const start = Date.now();
    let error: any = null;

    try {
      // Execute query
      const result = await query(sql, this.parameters);

      // Log query
      if (this.options.logQueries) {
        logger.debug('Delete query executed', {
          sql,
          params: this.parameters,
          duration: Date.now() - start,
          rows: result.rowCount,
        });
      }

      // Invalidate cache if needed
      if (this.options.enableCaching && this.cacheKey) {
        await redisCache.delete(this.cacheKey);
      }

      return result.rowCount;
    } catch (err) {
      error = err;

      // Log error
      logger.error('Delete query failed', {
        sql,
        params: this.parameters,
        error: err,
      });

      throw new DatabaseError(
        `Delete query failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
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

  /**
   * Execute a raw SQL query
   * @param sql SQL query
   * @param params Query parameters
   * @returns Query result
   */
  public async raw<T = any>(sql: string, params: any[] = []): Promise<T[]> {
    const start = Date.now();
    let error: any = null;

    try {
      // Execute query
      const result = await query(sql, params);

      // Log query
      if (this.options.logQueries) {
        logger.debug('Raw query executed', {
          sql,
          params,
          duration: Date.now() - start,
          rows: result.rowCount,
        });
      }

      return result.rows;
    } catch (err) {
      error = err;

      // Log error
      logger.error('Raw query failed', {
        sql,
        params,
        error: err,
      });

      throw new DatabaseError(
        `Raw query failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
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

  /**
   * Create a new query builder instance
   * @returns New query builder instance
   */
  public newQuery(): QueryBuilder {
    return new QueryBuilder(this.options);
  }

  /**
   * Clone the current query builder
   * @returns Cloned query builder instance
   */
  public clone(): QueryBuilder {
    const clone = new QueryBuilder(this.options);
    clone.table = this.table;
    clone.alias = this.alias;
    clone.selectColumns = [...this.selectColumns];
    clone.whereConditions = [...this.whereConditions];
    clone.joinClauses = [...this.joinClauses];
    clone.groupByColumns = [...this.groupByColumns];
    clone.havingConditions = [...this.havingConditions];
    clone.orderByClauses = [...this.orderByClauses];
    clone.limitValue = this.limitValue;
    clone.offsetValue = this.offsetValue;
    clone.parameters = [...this.parameters];
    clone.cacheKey = this.cacheKey;
    clone.cacheTTL = this.cacheTTL;
    return clone;
  }
}

/**
 * Create a new query builder instance
 * @param options Query builder options
 * @returns Query builder instance
 */
export function createQueryBuilder(options?: QueryBuilderOptions): QueryBuilder {
  return new QueryBuilder(options);
}

// Export a singleton instance
export const db = createQueryBuilder();
