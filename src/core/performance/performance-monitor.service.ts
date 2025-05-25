import { Injectable } from '@tsed/di';
import os from 'os';
import { logger } from '../../infrastructure/logging/logger';
import { performanceConfig } from '../../config/performance-config';
import { CacheService } from './cache.service';
import { DatabaseOptimizerService } from './database-optimizer.service';
import { SystemMetricsData, HealthStatus, CacheMetrics } from './types/metrics.types';

/**
 * Performance Monitor Service
 * Implements comprehensive performance monitoring and metrics collection
 */
@Injectable()
export class PerformanceMonitorService {
  private metricsInterval: NodeJS.Timeout | null = null;
  private startTime: number = Date.now();
  private requestMetrics: {
    total: number;
    success: number;
    error: number;
    avgResponseTime: number;
    responseTimeData: number[];
    pathStats: Map<string, { count: number; totalTime: number; avgTime: number }>;
  } = {
    total: 0,
    success: 0,
    error: 0,
    avgResponseTime: 0,
    responseTimeData: [],
    pathStats: new Map(),
  };

  constructor(
    private cacheService: CacheService,
    private databaseOptimizerService: DatabaseOptimizerService
  ) {
    if (performanceConfig.monitoring.enabled) {
      this.startMetricsCollection();
    }
  }

  /**
   * Start metrics collection
   */
  private startMetricsCollection(): void {
    this.metricsInterval = setInterval(
      () => this.collectMetrics(),
      performanceConfig.monitoring.interval
    );
    logger.info('Performance monitoring started', {
      interval: `${performanceConfig.monitoring.interval / 1000} seconds`,
    });
  }

  /**
   * Collect system metrics
   */
  private async collectMetrics(): Promise<void> {
    try {
      const metrics = (await this.getSystemMetrics()) as SystemMetricsData;

      // Store metrics in cache
      await this.cacheService.set(
        `${performanceConfig.cache.prefixes.metrics}:${Date.now()}`,
        metrics,
        { ttl: 86400 * 7 } // 7 days
      );

      // Log metrics summary
      logger.info('System metrics collected', {
        cpu: metrics['cpu']?.usage,
        memory: metrics['memory']?.usedPercentage,
        requests: metrics['http']?.requestsPerMinute,
        responseTime: metrics['http']?.avgResponseTime,
      });

      // Reset request metrics for next interval
      this.resetRequestMetrics();
    } catch (error) {
      logger.error('Failed to collect system metrics', { error });
    }
  }

  /**
   * Reset request metrics
   */
  private resetRequestMetrics(): void {
    this.requestMetrics = {
      total: 0,
      success: 0,
      error: 0,
      avgResponseTime: 0,
      responseTimeData: [],
      pathStats: new Map(),
    };
  }

  /**
   * Record request metrics
   * @param path Request path
   * @param method HTTP method
   * @param statusCode HTTP status code
   * @param responseTime Response time in milliseconds
   * @param userId User ID (optional)
   */
  recordRequestMetrics(
    path: string,
    method: string,
    statusCode: number,
    responseTime: number,
    userId?: string
  ): void {
    // Update total counts
    this.requestMetrics.total++;
    this.requestMetrics.responseTimeData.push(responseTime);

    // Update success/error counts
    if (statusCode >= 200 && statusCode < 400) {
      this.requestMetrics.success++;
    } else {
      this.requestMetrics.error++;
    }

    // Update path-specific stats
    const pathKey = `${method}:${path}`;
    let pathStats = this.requestMetrics.pathStats.get(pathKey);

    if (!pathStats) {
      pathStats = { count: 0, totalTime: 0, avgTime: 0 };
      this.requestMetrics.pathStats.set(pathKey, pathStats);
    }

    pathStats.count++;
    pathStats.totalTime += responseTime;
    pathStats.avgTime = pathStats.totalTime / pathStats.count;

    // Calculate overall average response time
    const sum = this.requestMetrics.responseTimeData.reduce((a, b) => a + b, 0);
    this.requestMetrics.avgResponseTime = sum / this.requestMetrics.responseTimeData.length;

    // Log slow requests
    if (responseTime > (performanceConfig.monitoring.slowRequestThreshold || 1000)) {
      logger.warn('Slow request detected', {
        path,
        method,
        responseTime,
        statusCode,
        userId,
      });
    }
  }

  /**
   * Get CPU load average safely
   * @returns CPU load average (first value from os.loadavg())
   */
  private getCpuLoadAverage(): number {
    try {
      const loadAvg = os.loadavg();
      // Ensure we have a valid load average value
      return Array.isArray(loadAvg) && loadAvg.length > 0 && typeof loadAvg[0] === 'number'
        ? loadAvg[0]
        : 0;
    } catch (error) {
      logger.warn('Failed to get CPU load average', { error });
      return 0;
    }
  }

  /**
   * Get system metrics
   * @returns System metrics
   */
  async getSystemMetrics(): Promise<SystemMetricsData> {
    try {
      // Calculate CPU usage with the new helper method
      const loadAvg = this.getCpuLoadAverage();
      const cpuCount = os.cpus().length || 1; // Ensure we never divide by zero
      const cpuUsage = (loadAvg / cpuCount) * 100;

      // Calculate memory usage
      const totalMemory = os.totalmem();
      const freeMemory = os.freemem();
      const usedMemory = totalMemory - freeMemory;
      const usedPercentage = (usedMemory / totalMemory) * 100;

      // Get database metrics
      const dbMetrics = await this.databaseOptimizerService.getDatabaseMetrics();

      // Calculate uptime
      const uptime = (Date.now() - this.startTime) / 1000; // seconds

      // Calculate request metrics
      const requestsPerMinute =
        this.requestMetrics.total / (performanceConfig.monitoring.interval / 60000);
      const successRate =
        this.requestMetrics.total > 0
          ? (this.requestMetrics.success / this.requestMetrics.total) * 100
          : 100;

      // Get top 5 slowest paths
      const slowestPaths = Array.from(this.requestMetrics.pathStats.entries())
        .sort((a, b) => b[1].avgTime - a[1].avgTime)
        .slice(0, 5)
        .map(([path, stats]) => ({
          path,
          avgResponseTime: stats.avgTime.toFixed(2),
          count: stats.count,
        }));

      // Get cache metrics
      const cacheMetrics = await this.getCacheMetrics();

      return {
        timestamp: new Date(),
        cpu: {
          usage: cpuUsage.toFixed(2),
          cores: os.cpus().length,
          loadAvg: os.loadavg(),
          model: os.cpus().length > 0 ? os.cpus()[0]?.model || 'Unknown' : 'Unknown',
        },
        memory: {
          total: this.formatBytes(totalMemory),
          used: this.formatBytes(usedMemory),
          free: this.formatBytes(freeMemory),
          usedPercentage: usedPercentage.toFixed(2),
        },
        system: {
          platform: os.platform(),
          arch: os.arch(),
          uptime: this.formatUptime(uptime),
          hostname: os.hostname(),
          nodeVersion: process.version,
        },
        http: {
          requests: this.requestMetrics.total,
          success: this.requestMetrics.success,
          error: this.requestMetrics.error,
          successRate: successRate.toFixed(2),
          requestsPerMinute: requestsPerMinute.toFixed(2),
          avgResponseTime: this.requestMetrics.avgResponseTime.toFixed(2),
          slowestPaths,
        },
        database: dbMetrics,
        cache: cacheMetrics,
        process: {
          pid: process.pid,
          memoryUsage: {
            rss: this.formatBytes(process.memoryUsage().rss),
            heapTotal: this.formatBytes(process.memoryUsage().heapTotal),
            heapUsed: this.formatBytes(process.memoryUsage().heapUsed),
            external: this.formatBytes(process.memoryUsage().external),
          },
          uptime: this.formatUptime(process.uptime()),
        },
      };
    } catch (error) {
      logger.error('Failed to get system metrics', { error });
      // Return a default SystemMetricsData object with error information
      return {
        timestamp: new Date(),
        cpu: { usage: '0', cores: 0, loadAvg: [0, 0, 0], model: 'Unknown' },
        memory: { total: '0B', used: '0B', free: '0B', usedPercentage: '0' },
        http: {
          requests: 0,
          success: 0,
          error: 0,
          successRate: '0',
          requestsPerMinute: '0',
          avgResponseTime: '0',
          slowestPaths: [],
        },
        system: {
          platform: os.platform(),
          arch: os.arch(),
          uptime: '0s',
          hostname: os.hostname(),
          nodeVersion: process.version,
        },
        database: {},
        cache: {
          hitRate: '0%',
          missRate: '0%',
          size: '0B',
          keys: 0,
          operations: { gets: 0, sets: 0, deletes: 0 },
        },
        process: {
          pid: process.pid,
          memoryUsage: { rss: '0B', heapTotal: '0B', heapUsed: '0B', external: '0B' },
          uptime: '0s',
        },
        error: 'Failed to collect metrics',
      };
    }
  }

  /**
   * Get cache metrics
   * @returns Cache metrics
   */
  private async getCacheMetrics(): Promise<CacheMetrics> {
    try {
      // In a real implementation, this would query cache metrics
      // For now, we'll return mock metrics
      return {
        hitRate: '85%',
        missRate: '15%',
        size: '250MB',
        keys: 1250,
        operations: {
          gets: 10000,
          sets: 2500,
          deletes: 500,
        },
      };
    } catch (error) {
      logger.error('Failed to get cache metrics', { error });
      return {
        hitRate: '0%',
        missRate: '0%',
        size: '0B',
        keys: 0,
        operations: {
          gets: 0,
          sets: 0,
          deletes: 0,
        },
      };
    }
  }

  /**
   * Format bytes to human-readable string
   * @param bytes Bytes
   * @returns Formatted string
   */
  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Number.parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  /**
   * Format uptime to human-readable string
   * @param seconds Uptime in seconds
   * @returns Formatted string
   */
  private formatUptime(seconds: number): string {
    const days = Math.floor(seconds / (3600 * 24));
    const hours = Math.floor((seconds % (3600 * 24)) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    const parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);

    return parts.join(' ');
  }

  /**
   * Get health check status
   * @returns Health check status
   */
  async getHealthCheck(): Promise<Record<string, any>> {
    try {
      // Check database connection
      const dbStatus = await this.checkDatabaseHealth();

      // Check cache connection
      const cacheStatus = await this.checkCacheHealth();

      // Check system resources
      const systemStatus = this.checkSystemHealth();

      // Determine overall status
      const isHealthy =
        dbStatus['status'] === 'healthy' &&
        cacheStatus['status'] === 'healthy' &&
        systemStatus['status'] === 'healthy';

      return {
        status: isHealthy ? 'healthy' : 'unhealthy',
        timestamp: new Date(),
        uptime: this.formatUptime((Date.now() - this.startTime) / 1000),
        components: {
          database: dbStatus,
          cache: cacheStatus,
          system: systemStatus,
        },
      };
    } catch (error) {
      logger.error('Health check failed', { error });
      return {
        status: 'unhealthy',
        timestamp: new Date(),
        error: (error as Error).message,
      };
    }
  }

  /**
   * Check database health
   * @returns Database health status
   */
  private async checkDatabaseHealth(): Promise<HealthStatus> {
    try {
      // In a real implementation, this would perform a simple query
      // For now, we'll assume the database is healthy if we can get metrics
      const metrics = await this.databaseOptimizerService.getDatabaseMetrics();
      return {
        status: 'healthy',
        responseTime: 5, // ms
        details: {
          connections: metrics['connectionPool']?.total || 'unknown',
        },
      };
    } catch (error) {
      logger.error('Database health check failed', { error });
      return {
        status: 'unhealthy',
        error: (error as Error).message,
      };
    }
  }

  /**
   * Check cache health
   * @returns Cache health status
   */
  private async checkCacheHealth(): Promise<HealthStatus> {
    try {
      // In a real implementation, this would perform a simple set/get operation
      // For now, we'll assume the cache is healthy if we can set a value
      const testKey = 'health:check';
      const testValue = { timestamp: Date.now() };
      const success = await this.cacheService.set(testKey, testValue, { ttl: 60 });

      return {
        status: success === true ? 'healthy' : 'unhealthy',
        responseTime: 2, // ms
      };
    } catch (error) {
      logger.error('Cache health check failed', { error });
      return {
        status: 'unhealthy',
        error: (error as Error).message,
      };
    }
  }

  /**
   * Check system health
   * @returns System health status
   */
  private checkSystemHealth(): HealthStatus {
    try {
      // Check CPU usage with the new helper method
      const loadAvg = this.getCpuLoadAverage();
      const cpuCount = os.cpus().length || 1; // Ensure we never divide by zero
      const cpuUsage = (loadAvg / cpuCount) * 100;
      const cpuHealthy = cpuUsage < 90; // CPU usage below 90%

      // Check memory usage
      const totalMemory = os.totalmem();
      const freeMemory = os.freemem();
      const memoryUsage = ((totalMemory - freeMemory) / totalMemory) * 100;
      const memoryHealthy = memoryUsage < 90; // Memory usage below 90%

      // Determine overall status
      const isHealthy = cpuHealthy && memoryHealthy;

      return {
        status: isHealthy ? 'healthy' : 'unhealthy',
        details: {
          cpu: {
            usage: cpuUsage.toFixed(2) + '%',
            status: cpuHealthy ? 'healthy' : 'unhealthy',
          },
          memory: {
            usage: memoryUsage.toFixed(2) + '%',
            status: memoryHealthy ? 'healthy' : 'unhealthy',
          },
        },
      };
    } catch (error) {
      logger.error('System health check failed', { error });
      return {
        status: 'unhealthy',
        error: (error as Error).message,
      };
    }
  }

  /**
   * Stop metrics collection
   */
  stop(): void {
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
      this.metricsInterval = null;
    }
  }
}
