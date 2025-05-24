import { EventEmitter } from 'events';
import { logger } from '../../infrastructure/logging/logger';
import { dbConfig } from '../../config/database-config';
import { getPostgresStatus } from './postgres';
import { getRedisStatus } from './redis';
import { checkDatabaseHealth as checkPrismaHealth } from '../prisma/client';
import { metricsCollector } from './metrics-collector';

/**
 * Health status
 */
export interface HealthStatus {
  status: 'ok' | 'error' | 'warning';
  details?: string | undefined;
  timestamp: number;
}

/**
 * Connection monitor options
 */
export interface ConnectionMonitorOptions {
  /**
   * Whether to enable connection monitoring
   * @default true
   */
  enabled?: boolean;

  /**
   * Monitoring interval in milliseconds
   * @default 30000 (30 seconds)
   */
  monitoringInterval?: number;

  /**
   * Maximum number of health records to keep in history
   * @default 100
   */
  maxHistorySize?: number;

  /**
   * Whether to emit events on health changes
   * @default true
   */
  emitEvents?: boolean;

  /**
   * Whether to log health changes
   * @default true
   */
  logHealthChanges?: boolean;
}

/**
 * Connection monitor
 * Monitors database connections and provides health information
 */
export class ConnectionMonitor extends EventEmitter {
  private static instance: ConnectionMonitor;
  private options: Required<ConnectionMonitorOptions>;
  private monitoringInterval: NodeJS.Timeout | null = null;
  private healthHistory: Map<string, HealthStatus[]> = new Map();
  private currentHealth: Map<string, HealthStatus> = new Map();
  private consecutiveFailures: Map<string, number> = new Map();
  private isMonitoring: boolean = false;

  /**
   * Private constructor to enforce singleton pattern
   * @param options Connection monitor options
   */
  private constructor(options?: ConnectionMonitorOptions) {
    super();

    // Set default options
    this.options = {
      enabled: options?.enabled ?? true,
      monitoringInterval: options?.monitoringInterval ?? 30000,
      maxHistorySize: options?.maxHistorySize ?? 100,
      emitEvents: options?.emitEvents ?? true,
      logHealthChanges: options?.logHealthChanges ?? true,
    };

    // Initialize health history
    this.healthHistory.set('postgres', []);
    this.healthHistory.set('redis', []);
    this.healthHistory.set('prisma', []);

    // Initialize current health
    this.currentHealth.set('postgres', { status: 'ok', timestamp: Date.now() });
    this.currentHealth.set('redis', { status: 'ok', timestamp: Date.now() });
    this.currentHealth.set('prisma', { status: 'ok', timestamp: Date.now() });

    // Initialize consecutive failures
    this.consecutiveFailures.set('postgres', 0);
    this.consecutiveFailures.set('redis', 0);
    this.consecutiveFailures.set('prisma', 0);
  }

  /**
   * Get the connection monitor instance
   * @param options Connection monitor options
   * @returns The connection monitor instance
   */
  public static getInstance(options?: ConnectionMonitorOptions): ConnectionMonitor {
    if (!ConnectionMonitor.instance) {
      ConnectionMonitor.instance = new ConnectionMonitor(options);
    }
    return ConnectionMonitor.instance;
  }

  /**
   * Start monitoring connections
   */
  public start(): void {
    if (!this.options.enabled) {
      logger.debug('Connection monitoring is disabled');
      return;
    }

    if (this.isMonitoring) {
      logger.debug('Connection monitoring is already running');
      return;
    }

    this.isMonitoring = true;

    // Check health immediately
    this.checkHealth().catch(error => {
      logger.error('Error checking connection health', { error });
    });

    // Start monitoring interval
    this.monitoringInterval = setInterval(() => {
      this.checkHealth().catch(error => {
        logger.error('Error checking connection health', { error });
      });
    }, this.options.monitoringInterval);

    logger.debug('Connection monitoring started', {
      interval: this.options.monitoringInterval,
    });
  }

  /**
   * Stop monitoring connections
   */
  public stop(): void {
    if (!this.isMonitoring) {
      logger.debug('Connection monitoring is not running');
      return;
    }

    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }

    this.isMonitoring = false;
    logger.debug('Connection monitoring stopped');
  }

  /**
   * Check the health of all connections
   * @returns Object with status and details for each connection
   */
  public async checkHealth(): Promise<{
    status: string;
    postgres: HealthStatus;
    redis: HealthStatus;
    prisma: HealthStatus;
  }> {
    try {
      // Check PostgreSQL health
      const postgresStatus = await getPostgresStatus();
      this.updateHealth('postgres', {
        status: postgresStatus.status as 'ok' | 'error' | 'warning',
        details: postgresStatus.details,
        timestamp: Date.now(),
      });

      // Check Redis health
      const redisStatus = await getRedisStatus();
      this.updateHealth('redis', {
        status: redisStatus.status as 'ok' | 'error' | 'warning',
        details: redisStatus.details,
        timestamp: Date.now(),
      });

      // Check Prisma health
      const prismaStatus = await checkPrismaHealth();
      this.updateHealth('prisma', {
        status: prismaStatus.status as 'ok' | 'error' | 'warning',
        details: prismaStatus.details,
        timestamp: Date.now(),
      });

      // Determine overall status
      const overallStatus =
        postgresStatus.status === 'ok' &&
        redisStatus.status === 'ok' &&
        prismaStatus.status === 'ok'
          ? 'ok'
          : 'error';

      return {
        status: overallStatus,
        postgres: this.currentHealth.get('postgres')!,
        redis: this.currentHealth.get('redis')!,
        prisma: this.currentHealth.get('prisma')!,
      };
    } catch (error) {
      logger.error('Error checking connection health', { error });

      return {
        status: 'error',
        postgres: { status: 'error', details: 'Failed to check health', timestamp: Date.now() },
        redis: { status: 'error', details: 'Failed to check health', timestamp: Date.now() },
        prisma: { status: 'error', details: 'Failed to check health', timestamp: Date.now() },
      };
    }
  }

  /**
   * Update the health of a service
   * @param service Service name
   * @param health Health status
   */
  private updateHealth(service: string, health: HealthStatus): void {
    // Get previous health
    const previousHealth = this.currentHealth.get(service);

    // Update current health
    this.currentHealth.set(service, health);

    // Update health history
    const history = this.healthHistory.get(service) || [];
    history.push(health);

    // Limit history size
    if (history.length > this.options.maxHistorySize) {
      history.shift();
    }

    this.healthHistory.set(service, history);

    // Update consecutive failures
    if (health.status === 'error') {
      const failures = (this.consecutiveFailures.get(service) || 0) + 1;
      this.consecutiveFailures.set(service, failures);

      // Log consecutive failures
      if (failures > 1) {
        logger.warn(`${service} connection has failed ${failures} times in a row`, {
          service,
          failures,
          details: health.details,
        });
      }
    } else {
      // Reset consecutive failures if service is healthy
      const previousFailures = this.consecutiveFailures.get(service) || 0;
      if (previousFailures > 0) {
        this.consecutiveFailures.set(service, 0);

        // Emit connection recovery event
        if (this.options.emitEvents) {
          this.emit('connection-recovery', service);
        }

        // Log connection recovery
        logger.info(`${service} connection has recovered after ${previousFailures} failures`, {
          service,
          previousFailures,
        });
      }
    }

    // Check if health status has changed
    if (previousHealth && previousHealth.status !== health.status) {
      // Log health change
      if (this.options.logHealthChanges) {
        if (health.status === 'ok') {
          logger.info(`${service} connection is now healthy`, {
            service,
            previousStatus: previousHealth.status,
            currentStatus: health.status,
            details: health.details,
          });
        } else {
          logger.warn(`${service} connection is now ${health.status}`, {
            service,
            previousStatus: previousHealth.status,
            currentStatus: health.status,
            details: health.details,
          });
        }
      }

      // Emit health change event
      if (this.options.emitEvents) {
        this.emit('health-change', service, health, previousHealth);

        if (health.status === 'error') {
          this.emit('connection-error', service, new Error(health.details));
        }
      }
    }

    // Update metrics
    if (service === 'postgres') {
      metricsCollector.setGauge('postgres.health', health.status === 'ok' ? 1 : 0);
    } else if (service === 'redis') {
      metricsCollector.setGauge('redis.health', health.status === 'ok' ? 1 : 0);
    } else if (service === 'prisma') {
      metricsCollector.setGauge('prisma.health', health.status === 'ok' ? 1 : 0);
    }
  }

  /**
   * Get the current health of all connections
   * @returns Object with status and details for each connection
   */
  public getCurrentHealth(): {
    status: string;
    postgres: HealthStatus;
    redis: HealthStatus;
    prisma: HealthStatus;
  } {
    const postgresHealth = this.currentHealth.get('postgres')!;
    const redisHealth = this.currentHealth.get('redis')!;
    const prismaHealth = this.currentHealth.get('prisma')!;

    // Determine overall status
    const overallStatus =
      postgresHealth.status === 'ok' && redisHealth.status === 'ok' && prismaHealth.status === 'ok'
        ? 'ok'
        : 'error';

    return {
      status: overallStatus,
      postgres: postgresHealth,
      redis: redisHealth,
      prisma: prismaHealth,
    };
  }

  /**
   * Get the health history for a service
   * @param service Service name
   * @returns Array of health statuses
   */
  public getHealthHistory(service: string): HealthStatus[] {
    return [...(this.healthHistory.get(service) || [])];
  }

  /**
   * Check if all connections are healthy
   * @returns True if all connections are healthy, false otherwise
   */
  public isHealthy(): boolean {
    const health = this.getCurrentHealth();
    return health.status === 'ok';
  }

  /**
   * Get the number of consecutive failures for a service
   * @param service Service name
   * @returns Number of consecutive failures
   */
  public getConsecutiveFailures(service: string): number {
    return this.consecutiveFailures.get(service) || 0;
  }

  /**
   * Reset the health history
   */
  public resetHealthHistory(): void {
    this.healthHistory.set('postgres', []);
    this.healthHistory.set('redis', []);
    this.healthHistory.set('prisma', []);

    logger.debug('Health history reset');
  }
}

// Export a singleton instance
export const connectionMonitor = ConnectionMonitor.getInstance();
