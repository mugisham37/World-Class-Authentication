import { logger } from '../../infrastructure/logging/logger';
import { dbConfig } from '../../config/database-config';
import { EventEmitter } from 'events';

/**
 * Metrics data point
 */
export interface MetricDataPoint {
  timestamp: number;
  value: number;
  tags: Record<string, string>;
}

/**
 * Metrics collector options
 */
export interface MetricsCollectorOptions {
  /**
   * Whether to enable metrics collection
   * @default true
   */
  enabled?: boolean;

  /**
   * Collection interval in milliseconds
   * @default 60000 (1 minute)
   */
  collectionInterval?: number;

  /**
   * Maximum number of data points to keep in memory
   * @default 1000
   */
  maxDataPoints?: number;

  /**
   * Whether to log metrics to the console
   * @default false
   */
  logMetrics?: boolean;
}

/**
 * Database metrics collector
 * Collects and stores metrics about database operations
 */
export class MetricsCollector extends EventEmitter {
  private static instance: MetricsCollector;
  private options: Required<MetricsCollectorOptions>;
  private collectionInterval: NodeJS.Timeout | null = null;
  private metrics: Map<string, MetricDataPoint[]> = new Map();
  private counters: Map<string, number> = new Map();
  private gauges: Map<string, number> = new Map();
  private histograms: Map<string, number[]> = new Map();

  /**
   * Private constructor to enforce singleton pattern
   * @param options Metrics collector options
   */
  private constructor(options?: MetricsCollectorOptions) {
    super();

    // Set default options
    this.options = {
      enabled: options?.enabled ?? dbConfig.metrics?.enabled ?? true,
      collectionInterval:
        options?.collectionInterval ?? dbConfig.metrics?.collectionInterval ?? 60000,
      maxDataPoints: options?.maxDataPoints ?? dbConfig.metrics?.maxDataPoints ?? 1000,
      logMetrics: options?.logMetrics ?? dbConfig.metrics?.logMetrics ?? false,
    };

    // Initialize metrics
    this.initializeMetrics();
  }

  /**
   * Get the metrics collector instance
   * @param options Metrics collector options
   * @returns The metrics collector instance
   */
  public static getInstance(options?: MetricsCollectorOptions): MetricsCollector {
    if (!MetricsCollector.instance) {
      MetricsCollector.instance = new MetricsCollector(options);
    }
    return MetricsCollector.instance;
  }

  /**
   * Initialize metrics
   */
  private initializeMetrics(): void {
    // Initialize counters
    this.counters.set('postgres.queries.total', 0);
    this.counters.set('postgres.queries.error', 0);
    this.counters.set('postgres.transactions.total', 0);
    this.counters.set('postgres.transactions.error', 0);
    this.counters.set('redis.operations.total', 0);
    this.counters.set('redis.operations.error', 0);
    this.counters.set('redis.cache.hits', 0);
    this.counters.set('redis.cache.misses', 0);
    this.counters.set('prisma.queries.total', 0);
    this.counters.set('prisma.queries.error', 0);

    // Initialize gauges
    this.gauges.set('postgres.pool.total', 0);
    this.gauges.set('postgres.pool.idle', 0);
    this.gauges.set('postgres.pool.used', 0);
    this.gauges.set('postgres.pool.waiting', 0);
    this.gauges.set('redis.memory.used', 0);
    this.gauges.set('redis.clients.connected', 0);

    // Initialize histograms
    this.histograms.set('postgres.query.duration', []);
    this.histograms.set('postgres.transaction.duration', []);
    this.histograms.set('redis.operation.duration', []);
    this.histograms.set('prisma.query.duration', []);

    // Initialize metrics
    this.metrics.set('postgres.queries.total', []);
    this.metrics.set('postgres.queries.error', []);
    this.metrics.set('postgres.transactions.total', []);
    this.metrics.set('postgres.transactions.error', []);
    this.metrics.set('redis.operations.total', []);
    this.metrics.set('redis.operations.error', []);
    this.metrics.set('redis.cache.hits', []);
    this.metrics.set('redis.cache.misses', []);
    this.metrics.set('prisma.queries.total', []);
    this.metrics.set('prisma.queries.error', []);
    this.metrics.set('postgres.pool.total', []);
    this.metrics.set('postgres.pool.idle', []);
    this.metrics.set('postgres.pool.used', []);
    this.metrics.set('postgres.pool.waiting', []);
    this.metrics.set('redis.memory.used', []);
    this.metrics.set('redis.clients.connected', []);
    this.metrics.set('postgres.query.duration.avg', []);
    this.metrics.set('postgres.query.duration.p95', []);
    this.metrics.set('postgres.query.duration.p99', []);
    this.metrics.set('postgres.transaction.duration.avg', []);
    this.metrics.set('postgres.transaction.duration.p95', []);
    this.metrics.set('postgres.transaction.duration.p99', []);
    this.metrics.set('redis.operation.duration.avg', []);
    this.metrics.set('redis.operation.duration.p95', []);
    this.metrics.set('redis.operation.duration.p99', []);
    this.metrics.set('prisma.query.duration.avg', []);
    this.metrics.set('prisma.query.duration.p95', []);
    this.metrics.set('prisma.query.duration.p99', []);
  }

  /**
   * Start collecting metrics
   */
  public startCollecting(): void {
    if (!this.options.enabled) {
      logger.debug('Metrics collection is disabled');
      return;
    }

    if (this.collectionInterval) {
      this.stopCollecting();
    }

    this.collectionInterval = setInterval(() => {
      this.collectMetrics();
    }, this.options.collectionInterval);

    logger.debug('Metrics collection started', {
      interval: this.options.collectionInterval,
      maxDataPoints: this.options.maxDataPoints,
    });
  }

  /**
   * Stop collecting metrics
   */
  public stopCollecting(): void {
    if (this.collectionInterval) {
      clearInterval(this.collectionInterval);
      this.collectionInterval = null;
      logger.debug('Metrics collection stopped');
    }
  }

  /**
   * Collect metrics
   */
  private collectMetrics(): void {
    try {
      const timestamp = Date.now();

      // Collect counter metrics
      for (const [name, value] of this.counters.entries()) {
        this.recordMetric(name, value, {}, timestamp);
      }

      // Collect gauge metrics
      for (const [name, value] of this.gauges.entries()) {
        this.recordMetric(name, value, {}, timestamp);
      }

      // Collect histogram metrics
      for (const [name, values] of this.histograms.entries()) {
        if (values.length > 0) {
          // Calculate statistics
          const avg = this.calculateAverage(values);
          const p95 = this.calculatePercentile(values, 95);
          const p99 = this.calculatePercentile(values, 99);

          // Record metrics
          this.recordMetric(`${name}.avg`, avg, {}, timestamp);
          this.recordMetric(`${name}.p95`, p95, {}, timestamp);
          this.recordMetric(`${name}.p99`, p99, {}, timestamp);

          // Clear histogram values
          this.histograms.set(name, []);
        }
      }

      // Log metrics if enabled
      if (this.options.logMetrics) {
        this.logCurrentMetrics();
      }

      // Emit metrics event
      this.emit('metrics', this.getMetrics());
    } catch (error) {
      logger.error('Error collecting metrics', { error });
    }
  }

  /**
   * Record a metric
   * @param name Metric name
   * @param value Metric value
   * @param tags Metric tags
   * @param timestamp Timestamp (optional, defaults to current time)
   */
  private recordMetric(
    name: string,
    value: number,
    tags: Record<string, string> = {},
    timestamp: number = Date.now()
  ): void {
    // Get metric data points
    const dataPoints = this.metrics.get(name) || [];

    // Add new data point
    dataPoints.push({
      timestamp,
      value,
      tags,
    });

    // Limit number of data points
    if (dataPoints.length > this.options.maxDataPoints) {
      dataPoints.shift();
    }

    // Update metrics
    this.metrics.set(name, dataPoints);
  }

  /**
   * Calculate average of values
   * @param values Array of values
   * @returns Average value
   */
  private calculateAverage(values: number[]): number {
    if (values.length === 0) {
      return 0;
    }

    const sum = values.reduce((a, b) => a + b, 0);
    return sum / values.length;
  }

  /**
   * Calculate percentile of values
   * @param values Array of values
   * @param percentile Percentile (0-100)
   * @returns Percentile value
   */
  private calculatePercentile(values: number[], percentile: number): number {
    if (values.length === 0) {
      return 0;
    }

    // Sort values
    const sortedValues = [...values].sort((a, b) => a - b);

    // Calculate index
    const index = Math.ceil((percentile / 100) * sortedValues.length) - 1;

    // Return percentile value
    return sortedValues[index];
  }

  /**
   * Log current metrics
   */
  private logCurrentMetrics(): void {
    const metrics: Record<string, number> = {};

    // Add counter metrics
    for (const [name, value] of this.counters.entries()) {
      metrics[name] = value;
    }

    // Add gauge metrics
    for (const [name, value] of this.gauges.entries()) {
      metrics[name] = value;
    }

    // Log metrics
    logger.debug('Current metrics', { metrics });
  }

  /**
   * Get all metrics
   * @returns Object with all metrics
   */
  public getMetrics(): Record<string, MetricDataPoint[]> {
    const result: Record<string, MetricDataPoint[]> = {};

    for (const [name, dataPoints] of this.metrics.entries()) {
      result[name] = [...dataPoints];
    }

    return result;
  }

  /**
   * Get a specific metric
   * @param name Metric name
   * @returns Array of data points
   */
  public getMetric(name: string): MetricDataPoint[] {
    return [...(this.metrics.get(name) || [])];
  }

  /**
   * Increment a counter
   * @param name Counter name
   * @param value Increment value (default: 1)
   * @param tags Counter tags
   */
  public incrementCounter(
    name: string,
    value: number = 1,
    tags: Record<string, string> = {}
  ): void {
    // Get current value
    const currentValue = this.counters.get(name) || 0;

    // Increment counter
    this.counters.set(name, currentValue + value);

    // Record metric immediately if enabled
    if (this.options.enabled) {
      this.recordMetric(name, currentValue + value, tags);
    }
  }

  /**
   * Set a gauge value
   * @param name Gauge name
   * @param value Gauge value
   * @param tags Gauge tags
   */
  public setGauge(name: string, value: number, tags: Record<string, string> = {}): void {
    // Set gauge value
    this.gauges.set(name, value);

    // Record metric immediately if enabled
    if (this.options.enabled) {
      this.recordMetric(name, value, tags);
    }
  }

  /**
   * Record a histogram value
   * @param name Histogram name
   * @param value Histogram value
   */
  public recordHistogram(name: string, value: number): void {
    // Get current values
    const values = this.histograms.get(name) || [];

    // Add value
    values.push(value);

    // Update histogram
    this.histograms.set(name, values);
  }

  /**
   * Track a PostgreSQL query
   * @param duration Query duration in milliseconds
   * @param isError Whether the query resulted in an error
   * @param isTransaction Whether the query was part of a transaction
   */
  public trackPostgresQuery(
    duration: number,
    isError: boolean = false,
    isTransaction: boolean = false
  ): void {
    // Increment counters
    this.incrementCounter('postgres.queries.total');

    if (isError) {
      this.incrementCounter('postgres.queries.error');
    }

    if (isTransaction) {
      this.incrementCounter('postgres.transactions.total');

      if (isError) {
        this.incrementCounter('postgres.transactions.error');
      }

      // Record transaction duration
      this.recordHistogram('postgres.transaction.duration', duration);
    } else {
      // Record query duration
      this.recordHistogram('postgres.query.duration', duration);
    }
  }

  /**
   * Track a Redis operation
   * @param duration Operation duration in milliseconds
   * @param isError Whether the operation resulted in an error
   * @param isCacheHit Whether the operation was a cache hit (true for hit, false for miss, null for non-cache operations)
   */
  public trackRedisOperation(
    duration: number,
    isError: boolean = false,
    isCacheHit: boolean | null | undefined = null
  ): void {
    // Increment counters
    this.incrementCounter('redis.operations.total');

    if (isError) {
      this.incrementCounter('redis.operations.error');
    }

    // Handle cache hit/miss metrics
    if (isCacheHit === true) {
      this.incrementCounter('redis.cache.hits');
    } else if (isCacheHit === false) {
      this.incrementCounter('redis.cache.misses');
    }

    // Record operation duration
    this.recordHistogram('redis.operation.duration', duration);
  }

  /**
   * Track a Prisma query
   * @param duration Query duration in milliseconds
   * @param isError Whether the query resulted in an error
   */
  public trackPrismaQuery(duration: number, isError: boolean = false): void {
    // Increment counters
    this.incrementCounter('prisma.queries.total');

    if (isError) {
      this.incrementCounter('prisma.queries.error');
    }

    // Record query duration
    this.recordHistogram('prisma.query.duration', duration);
  }

  /**
   * Update PostgreSQL pool metrics
   * @param total Total connections
   * @param idle Idle connections
   * @param used Used connections
   * @param waiting Waiting clients
   */
  public updatePostgresPoolMetrics(
    total: number,
    idle: number,
    used: number,
    waiting: number
  ): void {
    this.setGauge('postgres.pool.total', total);
    this.setGauge('postgres.pool.idle', idle);
    this.setGauge('postgres.pool.used', used);
    this.setGauge('postgres.pool.waiting', waiting);
  }

  /**
   * Update Redis metrics
   * @param memoryUsed Memory used in bytes
   * @param connectedClients Number of connected clients
   */
  public updateRedisMetrics(memoryUsed: number, connectedClients: number): void {
    this.setGauge('redis.memory.used', memoryUsed);
    this.setGauge('redis.clients.connected', connectedClients);
  }

  /**
   * Reset all metrics
   */
  public resetMetrics(): void {
    // Reset counters
    for (const name of this.counters.keys()) {
      this.counters.set(name, 0);
    }

    // Reset histograms
    for (const name of this.histograms.keys()) {
      this.histograms.set(name, []);
    }

    // Reset metrics
    for (const name of this.metrics.keys()) {
      this.metrics.set(name, []);
    }

    logger.debug('Metrics reset');
  }
}

// Export a singleton instance
export const metricsCollector = MetricsCollector.getInstance();
