import { logger } from '../../infrastructure/logging/logger';

/**
 * Interface for histogram statistics
 */
interface HistogramStats {
  min: number;
  max: number;
  avg: number;
  p95: number;
  p99: number;
}
/**
 * Metrics collector class
 * Collects and reports metrics for monitoring
 */
export class MetricsCollector {
  private static instance: MetricsCollector;
  private counters: Map<string, number>;
  private gauges: Map<string, number>;
  private histograms: Map<string, number[]>;
  private isCollecting: boolean = false;
  private collectionInterval: NodeJS.Timeout | null = null;
  private readonly COLLECTION_INTERVAL = 5000; // 5 seconds

  /**
   * Private constructor to enforce singleton pattern
   */
  private constructor() {
    this.counters = new Map<string, number>();
    this.gauges = new Map<string, number>();
    this.histograms = new Map<string, number[]>();
  }

  /**
   * Get the singleton instance
   * @returns The singleton instance
   */
  public static getInstance(): MetricsCollector {
    if (!MetricsCollector.instance) {
      MetricsCollector.instance = new MetricsCollector();
    }
    return MetricsCollector.instance;
  }

  /**
   * Increment a counter
   * @param name The counter name
   * @param value The increment value (default: 1)
   */
  public incrementCounter(name: string, value: number = 1): void {
    const currentValue = this.counters.get(name) || 0;
    this.counters.set(name, currentValue + value);
    logger.debug(`Counter ${name} incremented by ${value} to ${currentValue + value}`);
  }

  /**
   * Get a counter value
   * @param name The counter name
   * @returns The counter value
   */
  public getCounter(name: string): number {
    return this.counters.get(name) || 0;
  }

  /**
   * Reset a counter
   * @param name The counter name
   */
  public resetCounter(name: string): void {
    this.counters.set(name, 0);
    logger.debug(`Counter ${name} reset to 0`);
  }

  /**
   * Set a gauge value
   * @param name The gauge name
   * @param value The gauge value
   */
  public setGauge(name: string, value: number): void {
    this.gauges.set(name, value);
    logger.debug(`Gauge ${name} set to ${value}`);
  }

  /**
   * Increment a gauge
   * @param name The gauge name
   * @param value The increment value (default: 1)
   */
  public incrementGauge(name: string, value: number = 1): void {
    const currentValue = this.gauges.get(name) || 0;
    this.gauges.set(name, currentValue + value);
    logger.debug(`Gauge ${name} incremented by ${value} to ${currentValue + value}`);
  }

  /**
   * Decrement a gauge
   * @param name The gauge name
   * @param value The decrement value (default: 1)
   */
  public decrementGauge(name: string, value: number = 1): void {
    const currentValue = this.gauges.get(name) || 0;
    this.gauges.set(name, Math.max(0, currentValue - value));
    logger.debug(`Gauge ${name} decremented by ${value} to ${Math.max(0, currentValue - value)}`);
  }

  /**
   * Get a gauge value
   * @param name The gauge name
   * @returns The gauge value
   */
  public getGauge(name: string): number {
    return this.gauges.get(name) || 0;
  }

  /**
   * Observe a histogram value
   * @param name The histogram name
   * @param value The observed value
   */
  public observeHistogram(name: string, value: number): void {
    const values = this.histograms.get(name) || [];
    values.push(value);
    this.histograms.set(name, values);
    logger.debug(`Histogram ${name} observed value ${value}`);
  }

  /**
   * Get histogram values
   * @param name The histogram name
   * @returns The histogram values
   */
  public getHistogram(name: string): number[] {
    return this.histograms.get(name) || [];
  }

  /**
   * Get histogram statistics
   * @param name The histogram name
   * @returns The histogram statistics
   */
  public getHistogramStats(name: string): HistogramStats {
    const values = this.histograms.get(name) || [];
    if (values.length === 0) {
      return { min: 0, max: 0, avg: 0, p95: 0, p99: 0 };
    }

    const sortedValues = [...values].sort((a, b) => a - b);

    // We've already checked that values.length > 0, so these are safe
    // Using non-null assertion to tell TypeScript these won't be undefined
    const min = sortedValues[0]!;
    const max = sortedValues[sortedValues.length - 1]!;
    const avg = sortedValues.reduce((sum, val) => sum + val, 0) / sortedValues.length;

    // Calculate percentile indices with Math.min to ensure they're within bounds
    const p95Index = Math.min(Math.floor(sortedValues.length * 0.95), sortedValues.length - 1);
    const p99Index = Math.min(Math.floor(sortedValues.length * 0.99), sortedValues.length - 1);

    // Access array with guaranteed valid indices and non-null assertion
    const p95 = sortedValues[p95Index]!;
    const p99 = sortedValues[p99Index]!;

    return { min, max, avg, p95, p99 };
  }

  /**
   * Reset a histogram
   * @param name The histogram name
   */
  public resetHistogram(name: string): void {
    this.histograms.set(name, []);
    logger.debug(`Histogram ${name} reset`);
  }

  /**
   * Get all metrics
   * @returns All metrics
   */
  public getAllMetrics(): {
    counters: Map<string, number>;
    gauges: Map<string, number>;
    histograms: Map<string, number[]>;
  } {
    return {
      counters: this.counters,
      gauges: this.gauges,
      histograms: this.histograms,
    };
  }

  /**
   * Reset all metrics
   */
  public resetAllMetrics(): void {
    this.counters.clear();
    this.gauges.clear();
    this.histograms.clear();
    logger.debug('All metrics reset');
  }

  /**
   * Track Redis operation metrics
   * @param duration Operation duration in milliseconds
   * @param isError Whether operation resulted in error
   * @param isCacheHit Whether operation was a cache hit
   */
  public trackRedisOperation(duration: number, isError: boolean, isCacheHit: boolean): void {
    // Increment operation counter
    this.incrementCounter('redis.operations.total');

    // Track operation duration
    this.observeHistogram('redis.operation.duration', duration);

    // Track errors
    if (isError) {
      this.incrementCounter('redis.operations.errors');
    }

    // Track cache hits
    if (isCacheHit) {
      this.incrementCounter('redis.cache.hits');
    } else {
      this.incrementCounter('redis.cache.misses');
    }

    // Set current operation duration gauge
    this.setGauge('redis.operation.last_duration', duration);
  }

  /**
   * Track PostgreSQL query metrics
   * @param duration Query duration in milliseconds
   * @param isError Whether the query resulted in an error
   * @param isTransaction Whether the query was part of a transaction
   */
  public trackPostgresQuery(duration: number, isError: boolean, isTransaction: boolean): void {
    // Increment query counter
    this.incrementCounter('postgres.queries.total');

    // Track query duration
    this.observeHistogram('postgres.query.duration', duration);

    // Track errors
    if (isError) {
      this.incrementCounter('postgres.queries.errors');
    }

    // Track transactions
    if (isTransaction) {
      this.incrementCounter('postgres.queries.transactions');
    }

    // Set current query duration gauge
    this.setGauge('postgres.query.last_duration', duration);
  }

  /**
   * Start collecting metrics
   */
  public startCollecting(): void {
    if (this.isCollecting) {
      logger.debug('Metrics collection already started');
      return;
    }

    logger.info('Starting metrics collection');
    this.isCollecting = true;
    this.collectionInterval = setInterval(() => {
      this.collectMetrics();
    }, this.COLLECTION_INTERVAL);
  }

  /**
   * Stop collecting metrics
   */
  public stopCollecting(): void {
    if (!this.isCollecting || !this.collectionInterval) {
      logger.debug('Metrics collection not running');
      return;
    }

    logger.info('Stopping metrics collection');
    clearInterval(this.collectionInterval);
    this.collectionInterval = null;
    this.isCollecting = false;
  }

  /**
   * Collect current metrics
   * @private
   */
  private collectMetrics(): void {
    try {
      // Collect connection pool metrics
      this.collectPoolMetrics();

      // Collect query performance metrics
      this.collectQueryMetrics();

      // Collect cache metrics
      this.collectCacheMetrics();

      logger.debug('Metrics collection cycle completed');
    } catch (error) {
      // Log error but don't throw to prevent interval disruption
      logger.error('Error collecting metrics:', { error });
    }
  }

  /**
   * Collect connection pool metrics
   * @private
   */
  private collectPoolMetrics(): void {
    try {
      // Get current pool metrics from the gauges
      const totalConnections = this.getGauge('postgres.pool.total_connections');
      const activeConnections = this.getGauge('postgres.pool.active_connections');
      const idleConnections = this.getGauge('postgres.pool.idle_connections');

      // Calculate utilization percentage
      if (totalConnections > 0) {
        const utilizationPercentage = (activeConnections / totalConnections) * 100;
        this.setGauge('postgres.pool.utilization_percentage', utilizationPercentage);
      }

      // Track historical values
      this.observeHistogram('postgres.pool.active_connections_history', activeConnections);

      logger.debug('Pool metrics collected', {
        total: totalConnections,
        active: activeConnections,
        idle: idleConnections,
      });
    } catch (error) {
      logger.error('Error collecting pool metrics:', { error });
    }
  }

  /**
   * Collect query performance metrics
   * @private
   */
  private collectQueryMetrics(): void {
    try {
      // Get query metrics from counters and histograms
      const totalQueries = this.getCounter('postgres.queries.total');
      const errorQueries = this.getCounter('postgres.queries.errors');
      const transactionQueries = this.getCounter('postgres.queries.transactions');

      // Calculate error rate
      if (totalQueries > 0) {
        const errorRate = (errorQueries / totalQueries) * 100;
        this.setGauge('postgres.queries.error_rate', errorRate);
      }

      // Get query duration statistics
      const durationStats = this.getHistogramStats('postgres.query.duration');

      // Set gauges for query performance
      this.setGauge('postgres.query.avg_duration', durationStats.avg);
      this.setGauge('postgres.query.p95_duration', durationStats.p95);
      this.setGauge('postgres.query.p99_duration', durationStats.p99);

      logger.debug('Query metrics collected', {
        total: totalQueries,
        errors: errorQueries,
        transactions: transactionQueries,
        avgDuration: durationStats.avg,
      });
    } catch (error) {
      logger.error('Error collecting query metrics:', { error });
    }
  }

  /**
   * Collect cache metrics
   * @private
   */
  private collectCacheMetrics(): void {
    try {
      // Get cache metrics from gauges and counters
      const cacheHits = this.getCounter('redis.cache.hits');
      const cacheMisses = this.getCounter('redis.cache.misses');
      const cacheSize = this.getGauge('redis.cache.size');
      const memoryUsage = this.getGauge('redis.cache.memory_usage');

      // Calculate hit rate
      const totalRequests = cacheHits + cacheMisses;
      if (totalRequests > 0) {
        const hitRate = (cacheHits / totalRequests) * 100;
        this.setGauge('redis.cache.hit_rate', hitRate);
      }

      logger.debug('Cache metrics collected', {
        hits: cacheHits,
        misses: cacheMisses,
        size: cacheSize,
        memory: memoryUsage,
      });
    } catch (error) {
      logger.error('Error collecting cache metrics:', { error });
    }
  }
}

// Export a singleton instance
export const metricsCollector = MetricsCollector.getInstance();
