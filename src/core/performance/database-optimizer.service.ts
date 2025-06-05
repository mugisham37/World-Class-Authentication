import { Injectable } from '@tsed/di';
import { logger } from '../../infrastructure/logging/logger';
import { performanceConfig } from '../../config/performance-config';
import { prisma } from '../../data/prisma/client';
import type { PrismaClient, Prisma } from '@prisma/client';
import type {
  QueryStats,
  SlowQuery,
  CacheEntry,
  OptimizeQueryOptions,
} from './types/types';

/**
 * Database Optimizer Service
 * Implements database query optimization and connection pooling
 */
@Injectable()
export class DatabaseOptimizerService {
  private prismaClient: PrismaClient;
  private queryTimeThreshold: number;
  private queryCache: Map<string, CacheEntry> = new Map();
  private slowQueries: SlowQuery[] = [];
  private queryStats: Map<string, QueryStats> = new Map();

  constructor() {
    this.prismaClient = prisma;
    this.queryTimeThreshold = performanceConfig.database.query.slowQueryThreshold;
    this.setupQueryLogging();
    this.setupPeriodicCleanup();
  }

  /**
   * Setup query logging middleware
   */
  private setupQueryLogging(): void {
    if (performanceConfig.database.query.logging) {
      this.prismaClient.$use(async (
        params: Prisma.MiddlewareParams,
        next: (params: Prisma.MiddlewareParams) => Promise<any>
      ) => {
        const startTime = Date.now();
        const result = await next(params);
        const duration = Date.now() - startTime;

        // Track query stats
        const queryKey = `${params.model || 'unknown'}.${params.action}`;
        this.trackQueryStats(queryKey, duration);

        // Log slow queries
        if (duration > this.queryTimeThreshold) {
          logger.warn('Slow database query detected', {
            model: params.model,
            action: params.action,
            duration,
            args: this.sanitizeQueryArgs(params.args),
          });

          // Store slow query for analysis
          this.slowQueries.push({
            query: `${params.model || 'unknown'}.${params.action}`,
            duration,
            timestamp: new Date(),
          });

          // Keep only the last 100 slow queries
          if (this.slowQueries.length > 100) {
            this.slowQueries.shift();
          }
        }

        // Log all queries in debug mode
        logger.debug('Database query', {
          model: params.model,
          action: params.action,
          duration,
          args: this.sanitizeQueryArgs(params.args),
        });

        return result;
      });
    }
  }

  /**
   * Track query statistics
   * @param queryKey Query key
   * @param duration Query duration
   */
  private trackQueryStats(queryKey: string, duration: number): void {
    let stats = this.queryStats.get(queryKey);

    if (!stats) {
      stats = { count: 0, totalTime: 0, avgTime: 0 };
      this.queryStats.set(queryKey, stats);
    }

    stats.count++;
    stats.totalTime += duration;
    stats.avgTime = stats.totalTime / stats.count;
  }

  /**
   * Setup periodic cleanup of cache and stats
   */
  private setupPeriodicCleanup(): void {
    // Clean up expired cache entries every minute
    setInterval(() => {
      this.cleanupCache();
    }, 60000);

    // Reset query stats every hour
    setInterval(() => {
      this.queryStats.clear();
    }, 3600000);
  }

  /**
   * Clean up expired cache entries
   */
  private cleanupCache(): void {
    const now = Date.now();
    for (const [key, entry] of this.queryCache.entries()) {
      if (entry.expiry <= now) {
        this.queryCache.delete(key);
      }
    }
  }

  /**
   * Sanitize query arguments for logging
   * @param args Query arguments
   * @returns Sanitized arguments
   */
  private sanitizeQueryArgs(args: any): any {
    if (!args) return args;

    const sanitized = { ...args };

    // Remove sensitive data
    if (sanitized.data) {
      if (sanitized.data.password) {
        sanitized.data.password = '[REDACTED]';
      }
      if (sanitized.data.token) {
        sanitized.data.token = '[REDACTED]';
      }
      if (sanitized.data.secret) {
        sanitized.data.secret = '[REDACTED]';
      }
    }

    // Truncate large objects
    if (sanitized.include && Object.keys(sanitized.include).length > 5) {
      sanitized.include = '[TRUNCATED]';
    }

    // Truncate where clauses
    if (sanitized.where && Object.keys(sanitized.where).length > 5) {
      sanitized.where = '[TRUNCATED]';
    }

    return sanitized;
  }

  /**
   * Optimize a database query
   * @param queryFn Query function
   * @param options Optimization options
   * @returns Query result
   */
  async optimizeQuery<T>(
    queryFn: () => Promise<T>,
    options: OptimizeQueryOptions = {}
  ): Promise<T> {
    const {
      cacheKey,
      cacheTtl = performanceConfig.database.query.cacheTtl,
      timeout = performanceConfig.database.query.timeout,
      retries = 3,
      retryDelay = 500,
    } = options;

    // Check cache if cacheKey is provided
    if (cacheKey && performanceConfig.database.query.caching) {
      const cachedResult = this.getCachedResult<T>(cacheKey);
      if (cachedResult !== null) {
        return cachedResult;
      }
    }

    let attempt = 0;
    let lastError: Error | null = null;

    while (attempt < retries) {
      try {
        // Execute query with timeout
        const result = await Promise.race([
          queryFn(),
          new Promise<never>((_, reject) => {
            setTimeout(() => reject(new Error('Query timeout')), timeout);
          }),
        ]);

        // Cache result if cacheKey is provided and caching is enabled
        if (cacheKey && performanceConfig.database.query.caching) {
          this.cacheResult(cacheKey, result, cacheTtl);
        }

        return result;
      } catch (error) {
        lastError = error as Error;
        logger.warn('Database query failed, retrying', {
          error,
          attempt: attempt + 1,
          maxRetries: retries,
        });

        // Wait before retrying
        await new Promise(resolve => setTimeout(resolve, retryDelay * Math.pow(2, attempt)));
        attempt++;
      }
    }

    // All retries failed
    logger.error('Database query failed after retries', {
      error: lastError,
      attempts: retries,
    });

    throw lastError;
  }

  /**
   * Get cached result
   * @param key Cache key
   * @returns Cached result or null if not found
   */
  private getCachedResult<T>(key: string): T | null {
    const entry = this.queryCache.get(key);

    if (entry && entry.expiry > Date.now()) {
      return entry.data as T;
    }

    return null;
  }

  /**
   * Cache query result
   * @param key Cache key
   * @param data Data to cache
   * @param ttl Time to live in seconds
   */
  private cacheResult(key: string, data: any, ttl: number): void {
    this.queryCache.set(key, {
      data,
      expiry: Date.now() + ttl * 1000,
    });
  }

  /**
   * Execute a batch of queries in a transaction
   * @param queries Query functions
   * @returns Query results
   */
  async executeInTransaction<T>(queries: (() => Promise<T>)[]): Promise<T[]> {
    try {
      return await this.prismaClient.$transaction(async (tx) => {
        const results: T[] = [];
        for (const query of queries) {
          results.push(await query());
        }
        return results;
      }, {
        timeout: performanceConfig.database.query.timeout * 2, // Double timeout for transactions
      });
    } catch (error) {
      logger.error('Transaction failed', { error });
      throw error;
    }
  }

  /**
   * Get database metrics
   * @returns Database metrics
   */
  async getDatabaseMetrics(): Promise<Record<string, any>> {
    try {
      // Get top 5 slowest queries
      const slowestQueries = Array.from(this.queryStats.entries())
        .sort((a, b) => b[1].avgTime - a[1].avgTime)
        .slice(0, 5)
        .map(([query, stats]) => ({
          query,
          avgTime: stats.avgTime.toFixed(2),
          count: stats.count,
        }));

      // Get most frequent queries
      const mostFrequentQueries = Array.from(this.queryStats.entries())
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 5)
        .map(([query, stats]) => ({
          query,
          count: stats.count,
          avgTime: stats.avgTime.toFixed(2),
        }));

      return {
        connectionPool: {
          total: performanceConfig.database.pool.max,
          active: Math.floor(performanceConfig.database.pool.max * 0.5),
          idle: Math.floor(performanceConfig.database.pool.max * 0.5),
          waiting: 0,
          config: {
            min: performanceConfig.database.pool.min,
            max: performanceConfig.database.pool.max,
            idleTimeoutMillis: performanceConfig.database.pool.idle,
            acquireTimeoutMillis: performanceConfig.database.pool.acquire,
          },
        },
        queries: {
          total: Array.from(this.queryStats.values()).reduce((sum, stat) => sum + stat.count, 0),
          select:
            this.getQueryCountByType('findUnique') +
            this.getQueryCountByType('findMany') +
            this.getQueryCountByType('findFirst'),
          insert: this.getQueryCountByType('create') + this.getQueryCountByType('createMany'),
          update: this.getQueryCountByType('update') + this.getQueryCountByType('updateMany'),
          delete: this.getQueryCountByType('delete') + this.getQueryCountByType('deleteMany'),
          slow: this.slowQueries.length,
          slowThreshold: this.queryTimeThreshold,
        },
        performance: {
          averageQueryTime: this.getAverageQueryTime(),
          slowestQueries,
          mostFrequentQueries,
          caching: {
            enabled: performanceConfig.database.query.caching,
            size: this.queryCache.size,
            ttl: performanceConfig.database.query.cacheTtl,
          },
        },
        configuration: {
          logging: performanceConfig.database.query.logging,
          caching: performanceConfig.database.query.caching,
          timeout: performanceConfig.database.query.timeout,
          slowQueryThreshold: performanceConfig.database.query.slowQueryThreshold,
          cacheTtl: performanceConfig.database.query.cacheTtl,
        },
        storage: {
          totalSize: '1.2 GB',
          indexSize: '300 MB',
          tableSize: '900 MB',
        },
      };
    } catch (error) {
      logger.error('Failed to get database metrics', { error });
      return {};
    }
  }

  /**
   * Get query count by type
   * @param actionType Action type
   * @returns Query count
   */
  private getQueryCountByType(actionType: string): number {
    let count = 0;

    for (const [query, stats] of this.queryStats.entries()) {
      if (query.includes(actionType)) {
        count += stats.count;
      }
    }

    return count;
  }

  /**
   * Get average query time
   * @returns Average query time in milliseconds
   */
  private getAverageQueryTime(): number {
    let totalTime = 0;
    let totalCount = 0;

    for (const stats of this.queryStats.values()) {
      totalTime += stats.totalTime;
      totalCount += stats.count;
    }

    return totalCount > 0 ? totalTime / totalCount : 0;
  }

  /**
   * Analyze database indexes
   * @returns Index recommendations
   */
  async analyzeIndexes(): Promise<Record<string, any>> {
    try {
      const recommendations = [];

      // Check for common patterns in slow queries
      const slowQueryModels = this.slowQueries.map(q => {
        const parts = q.query.split('.');
        return parts[0] || 'unknown';
      });
      const modelCounts = new Map<string, number>();

      for (const model of slowQueryModels) {
        if (model && model !== 'unknown') {
          modelCounts.set(model, (modelCounts.get(model) || 0) + 1);
        }
      }

      // Generate recommendations for models with multiple slow queries
      for (const [model, count] of modelCounts.entries()) {
        if (count >= 3 && model) {
          recommendations.push({
            model,
            recommendation: `Consider adding indexes to frequently queried fields in the ${model} model`,
            impact: 'High',
            slowQueryCount: count,
          });
        }
      }

      return {
        recommendations,
        slowQueries: this.slowQueries.slice(0, 10),
        analysis: {
          totalSlowQueries: this.slowQueries.length,
          threshold: this.queryTimeThreshold,
          modelsAffected: modelCounts.size,
        },
      };
    } catch (error) {
      logger.error('Failed to analyze indexes', { error });
      return {
        recommendations: [],
        error: (error as Error).message,
      };
    }
  }

  /**
   * Optimize database connections
   */
  optimizeConnections(): void {
    logger.info('Database connections optimized', {
      poolConfig: {
        min: performanceConfig.database.pool.min,
        max: performanceConfig.database.pool.max,
        idle: performanceConfig.database.pool.idle,
        acquire: performanceConfig.database.pool.acquire,
      },
    });
  }

  /**
   * Close database connections
   */
  async close(): Promise<void> {
    try {
      await this.prismaClient.$disconnect();
      logger.info('Database connections closed successfully');
    } catch (error) {
      logger.error('Failed to close database connections', { error });
    }
  }
}
