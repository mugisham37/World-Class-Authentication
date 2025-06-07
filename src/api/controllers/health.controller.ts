import type { Request, Response } from 'express';
import { BaseController } from './base.controller';
import { logger } from '../../infrastructure/logging/logger';
import { getPostgresConnection } from '../../data/connections/postgres.connection';
import { getRedisStatus } from '../../data/connections/redis';
import { sendOkResponse } from '../responses';

/**
 * Health check controller
 * Provides endpoints to check the health of the application and its dependencies
 */
export class HealthController extends BaseController {
  /**
   * Basic health check
   * @route GET /health
   */
  getHealth = this.handleAsync(async (_req: Request, res: Response): Promise<void> => {
    sendOkResponse(res, 'Health check successful', {
      status: 'ok',
      timestamp: new Date().toISOString(),
      service: 'auth-service',
    });
  });

  /**
   * Detailed health check with component status
   * @route GET /health/detailed
   */
  getDetailedHealth = this.handleAsync(async (_req: Request, res: Response): Promise<void> => {
    try {
      // Check database connections
      const postgresConnection = getPostgresConnection();
      const postgresStatus = (await postgresConnection.healthCheck())
        ? { status: 'ok', details: 'PostgreSQL connection is healthy' }
        : { status: 'error', details: 'PostgreSQL connection is unhealthy' };
      const redisStatus = await getRedisStatus();

      // Determine overall status
      const isHealthy = postgresStatus.status === 'ok' && redisStatus.status === 'ok';

      const healthData = {
        status: isHealthy ? 'ok' : 'degraded',
        timestamp: new Date().toISOString(),
        service: 'auth-service',
        components: {
          postgres: postgresStatus,
          redis: redisStatus,
        },
        uptime: process.uptime(),
        memory: process.memoryUsage(),
      };

      // Log health check results if there are issues
      if (!isHealthy) {
        logger.warn('Health check detected issues', { healthData });
      }

      sendOkResponse(res, 'Detailed health check', healthData);
    } catch (error) {
      logger.error('Health check failed', { error });
      throw error;
    }
  });

  /**
   * Readiness check for load balancers
   * @route GET /health/ready
   */
  getReadiness = this.handleAsync(async (_req: Request, res: Response): Promise<void> => {
    try {
      // Check database connections
      const postgresConnection = getPostgresConnection();
      const postgresStatus = (await postgresConnection.healthCheck())
        ? { status: 'ok', details: 'PostgreSQL connection is healthy' }
        : { status: 'error', details: 'PostgreSQL connection is unhealthy' };
      const redisStatus = await getRedisStatus();

      // Determine if service is ready
      const isReady = postgresStatus.status === 'ok' && redisStatus.status === 'ok';

      if (!isReady) {
        logger.warn('Service not ready', {
          postgres: postgresStatus,
          redis: redisStatus,
        });

        // Return 503 Service Unavailable if not ready
        res.status(503).json({
          status: 'error',
          message: 'Service not ready',
          timestamp: new Date().toISOString(),
          components: {
            postgres: postgresStatus,
            redis: redisStatus,
          },
        });
        return;
      }

      sendOkResponse(res, 'Service ready', {
        status: 'ok',
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Readiness check failed', { error });
      throw error;
    }
  });

  /**
   * Liveness check for orchestrators
   * @route GET /health/live
   */
  getLiveness = this.handleAsync(async (_req: Request, res: Response): Promise<void> => {
    // This is a simple check to verify the application is running
    // It doesn't check dependencies, just that the app is responsive
    sendOkResponse(res, 'Service alive', {
      status: 'ok',
      timestamp: new Date().toISOString(),
    });
  });

  /**
   * Application metrics for monitoring systems
   * @route GET /metrics
   */
  getMetrics = this.handleAsync(async (_req: Request, res: Response): Promise<void> => {
    // Collect basic metrics
    const metrics = {
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
      // Add more metrics as needed
    };

    sendOkResponse(res, 'Application metrics', metrics);
  });
}

// Create instance
export const healthController = new HealthController();
