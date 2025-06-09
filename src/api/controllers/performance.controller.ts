import type { Response } from 'express';
import { BaseController, ExtendedRequest } from './base.controller';
import { sendOkResponse } from '../responses';
import { AuthenticationError } from '../../utils/error-handling';
import { logger } from '../../infrastructure/logging/logger';

/**
 * Performance controller
 * Handles performance monitoring and metrics endpoints
 */
export class PerformanceController extends BaseController {
  /**
   * Get system metrics
   * @route GET /performance/metrics
   */
  getMetrics = this.handleAsync(async (req: ExtendedRequest, res: Response): Promise<void> => {
    // Check if user is authenticated and has admin role
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    // In a real implementation, check if user has admin role
    // For now, we'll just assume they do

    try {
      // In a real implementation, this would query the performance monitoring service
      // For now, we'll just return mock data
      const metrics = {
        timestamp: new Date(),
        system: {
          cpuUsage: 25.4,
          memoryUsage: {
            total: 8192,
            used: 4096,
            free: 4096,
            percentUsed: 50,
          },
          uptime: 86400, // 1 day in seconds
          nodeVersion: process.version,
        },
        application: {
          requestsPerMinute: 120,
          averageResponseTime: 45, // ms
          errorRate: 0.5, // percentage
          activeUsers: 250,
          activeSessions: 300,
        },
        database: {
          connectionPoolSize: 20,
          activeConnections: 8,
          queryExecutionTime: 12, // ms
          slowQueries: 2,
        },
        cache: {
          hitRate: 85, // percentage
          missRate: 15, // percentage
          size: 1024, // KB
          itemCount: 5000,
        },
        authentication: {
          successfulLogins: 500,
          failedLogins: 25,
          mfaUsage: 75, // percentage
          passwordResets: 10,
        },
      };

      sendOkResponse(res, 'System metrics retrieved successfully', metrics);
    } catch (error) {
      logger.error('Error getting system metrics', { error, userId: req.user?.id });
      throw error;
    }
  });

  /**
   * Get performance dashboard data
   * @route GET /performance/dashboard
   */
  getDashboardData = this.handleAsync(
    async (req: ExtendedRequest, res: Response): Promise<void> => {
      // Check if user is authenticated and has admin role
      if (!req.user) {
        throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
      }

      // In a real implementation, check if user has admin role
      // For now, we'll just assume they do

      try {
        // Get time range from query parameters
        const timeRange = (req.query['timeRange'] as string) || '24h';

        // In a real implementation, this would query the performance monitoring service
        // For now, we'll just return mock data
        const dashboardData = {
          timeRange,
          summary: {
            totalRequests: 25000,
            averageResponseTime: 45, // ms
            p95ResponseTime: 120, // ms
            p99ResponseTime: 250, // ms
            errorRate: 0.5, // percentage
            uniqueUsers: 1200,
          },
          charts: {
            requestsOverTime: Array.from({ length: 24 }, (_, i) => ({
              timestamp: new Date(Date.now() - (23 - i) * 3600000),
              value: 800 + Math.floor(Math.random() * 400),
            })),
            responseTimeOverTime: Array.from({ length: 24 }, (_, i) => ({
              timestamp: new Date(Date.now() - (23 - i) * 3600000),
              value: 40 + Math.floor(Math.random() * 20),
            })),
            errorRateOverTime: Array.from({ length: 24 }, (_, i) => ({
              timestamp: new Date(Date.now() - (23 - i) * 3600000),
              value: 0.2 + Math.random() * 0.8,
            })),
            activeUsersOverTime: Array.from({ length: 24 }, (_, i) => ({
              timestamp: new Date(Date.now() - (23 - i) * 3600000),
              value: 200 + Math.floor(Math.random() * 200),
            })),
          },
          topEndpoints: [
            {
              path: '/api/auth/login',
              requestCount: 5000,
              averageResponseTime: 60,
              errorRate: 0.8,
            },
            {
              path: '/api/auth/refresh',
              requestCount: 4500,
              averageResponseTime: 30,
              errorRate: 0.2,
            },
            {
              path: '/api/user/profile',
              requestCount: 3000,
              averageResponseTime: 50,
              errorRate: 0.3,
            },
            {
              path: '/api/auth/logout',
              requestCount: 2500,
              averageResponseTime: 25,
              errorRate: 0.1,
            },
            {
              path: '/api/mfa/verify',
              requestCount: 2000,
              averageResponseTime: 70,
              errorRate: 1.2,
            },
          ],
          slowestEndpoints: [
            {
              path: '/api/user/activity-log',
              averageResponseTime: 250,
              requestCount: 500,
            },
            {
              path: '/api/compliance/data-export',
              averageResponseTime: 200,
              requestCount: 50,
            },
            {
              path: '/api/audit/logs',
              averageResponseTime: 180,
              requestCount: 300,
            },
            {
              path: '/api/risk/assessment',
              averageResponseTime: 150,
              requestCount: 800,
            },
            {
              path: '/api/mfa/setup',
              averageResponseTime: 120,
              requestCount: 600,
            },
          ],
        };

        sendOkResponse(res, 'Dashboard data retrieved successfully', dashboardData);
      } catch (error) {
        logger.error('Error getting dashboard data', {
          error,
          userId: req.user?.id,
          timeRange: req.query['timeRange'],
        });
        throw error;
      }
    }
  );

  /**
   * Get real-time performance data
   * @route GET /performance/real-time
   */
  getRealTimeData = this.handleAsync(async (req: ExtendedRequest, res: Response): Promise<void> => {
    // Check if user is authenticated and has admin role
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    // In a real implementation, check if user has admin role
    // For now, we'll just assume they do

    try {
      // In a real implementation, this would query the performance monitoring service
      // For now, we'll just return mock data
      const realTimeData = {
        timestamp: new Date(),
        activeUsers: 250 + Math.floor(Math.random() * 50),
        requestsPerSecond: 5 + Math.floor(Math.random() * 5),
        currentResponseTime: 40 + Math.floor(Math.random() * 20),
        cpuUsage: 20 + Math.floor(Math.random() * 10),
        memoryUsage: 45 + Math.floor(Math.random() * 10),
        activeConnections: {
          database: 5 + Math.floor(Math.random() * 5),
          redis: 3 + Math.floor(Math.random() * 3),
        },
        errorCount: Math.floor(Math.random() * 3),
      };

      sendOkResponse(res, 'Real-time performance data retrieved successfully', realTimeData);
    } catch (error) {
      logger.error('Error getting real-time performance data', { error, userId: req.user?.id });
      throw error;
    }
  });

  /**
   * Get performance alerts
   * @route GET /performance/alerts
   */
  getAlerts = this.handleAsync(async (req: ExtendedRequest, res: Response): Promise<void> => {
    // Check if user is authenticated and has admin role
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    // In a real implementation, check if user has admin role
    // For now, we'll just assume they do

    try {
      // Get status filter from query parameters
      const status = (req.query['status'] as string) || 'active';

      // In a real implementation, this would query the performance monitoring service
      // For now, we'll just return mock data
      const alerts = {
        active: [
          {
            id: 'alert_1',
            type: 'HIGH_CPU_USAGE',
            severity: 'WARNING',
            message: 'CPU usage above 80% for more than 5 minutes',
            timestamp: new Date(Date.now() - 300000), // 5 minutes ago
            value: 85,
            threshold: 80,
            duration: 300, // seconds
          },
          {
            id: 'alert_2',
            type: 'HIGH_ERROR_RATE',
            severity: 'CRITICAL',
            message: 'Error rate above 5% for more than 10 minutes',
            timestamp: new Date(Date.now() - 600000), // 10 minutes ago
            value: 7.5,
            threshold: 5,
            duration: 600, // seconds
            affectedEndpoints: ['/api/auth/login', '/api/mfa/verify'],
          },
        ],
        resolved: [
          {
            id: 'alert_3',
            type: 'SLOW_RESPONSE_TIME',
            severity: 'WARNING',
            message: 'Average response time above 200ms for more than 15 minutes',
            timestamp: new Date(Date.now() - 3600000), // 1 hour ago
            resolvedAt: new Date(Date.now() - 3300000), // 55 minutes ago
            value: 250,
            threshold: 200,
            duration: 900, // seconds
            affectedEndpoints: ['/api/user/activity-log', '/api/compliance/data-export'],
          },
          {
            id: 'alert_4',
            type: 'DATABASE_CONNECTION_POOL_EXHAUSTED',
            severity: 'CRITICAL',
            message: 'Database connection pool utilization at 100% for more than 2 minutes',
            timestamp: new Date(Date.now() - 7200000), // 2 hours ago
            resolvedAt: new Date(Date.now() - 7080000), // 1 hour 58 minutes ago
            value: 100,
            threshold: 90,
            duration: 120, // seconds
          },
        ],
      };

      sendOkResponse(
        res,
        'Performance alerts retrieved successfully',
        status === 'active' ? alerts.active : alerts.resolved
      );
    } catch (error) {
      logger.error('Error getting performance alerts', {
        error,
        userId: req.user?.id,
        status: req.query['status'],
      });
      throw error;
    }
  });

  /**
   * Get database performance metrics
   * @route GET /performance/database
   */
  getDatabaseMetrics = this.handleAsync(
    async (req: ExtendedRequest, res: Response): Promise<void> => {
      // Check if user is authenticated and has admin role
      if (!req.user) {
        throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
      }

      // In a real implementation, check if user has admin role
      // For now, we'll just assume they do

      try {
        // In a real implementation, this would query the performance monitoring service
        // For now, we'll just return mock data
        const databaseMetrics = {
          timestamp: new Date(),
          connectionPool: {
            size: 20,
            active: 8,
            idle: 12,
            waitingRequests: 0,
            maxUsage: 15, // Maximum connections used at once
          },
          queryPerformance: {
            averageExecutionTime: 12, // ms
            slowestQueries: [
              {
                query:
                  'SELECT * FROM users JOIN user_sessions ON users.id = user_sessions.user_id WHERE users.last_active_at > ?',
                averageTime: 150, // ms
                executionCount: 120,
                lastExecuted: new Date(Date.now() - 60000), // 1 minute ago
              },
              {
                query:
                  'SELECT * FROM audit_logs WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC',
                averageTime: 120, // ms
                executionCount: 50,
                lastExecuted: new Date(Date.now() - 120000), // 2 minutes ago
              },
              {
                query:
                  'SELECT * FROM mfa_factors JOIN users ON mfa_factors.user_id = users.id WHERE users.email LIKE ?',
                averageTime: 100, // ms
                executionCount: 30,
                lastExecuted: new Date(Date.now() - 180000), // 3 minutes ago
              },
            ],
            queryTypes: {
              select: 80, // percentage
              insert: 15, // percentage
              update: 4, // percentage
              delete: 1, // percentage
            },
          },
          tables: [
            {
              name: 'users',
              rowCount: 10000,
              sizeKB: 2048,
              indexSizeKB: 512,
              lastVacuumed: new Date(Date.now() - 86400000), // 1 day ago
            },
            {
              name: 'sessions',
              rowCount: 5000,
              sizeKB: 1024,
              indexSizeKB: 256,
              lastVacuumed: new Date(Date.now() - 86400000), // 1 day ago
            },
            {
              name: 'audit_logs',
              rowCount: 100000,
              sizeKB: 8192,
              indexSizeKB: 2048,
              lastVacuumed: new Date(Date.now() - 86400000), // 1 day ago
            },
            {
              name: 'mfa_factors',
              rowCount: 8000,
              sizeKB: 1024,
              indexSizeKB: 256,
              lastVacuumed: new Date(Date.now() - 86400000), // 1 day ago
            },
            {
              name: 'recovery_methods',
              rowCount: 5000,
              sizeKB: 512,
              indexSizeKB: 128,
              lastVacuumed: new Date(Date.now() - 86400000), // 1 day ago
            },
          ],
        };

        sendOkResponse(res, 'Database metrics retrieved successfully', databaseMetrics);
      } catch (error) {
        logger.error('Error getting database metrics', { error, userId: req.user?.id });
        throw error;
      }
    }
  );

  /**
   * Get cache performance metrics
   * @route GET /performance/cache
   */
  getCacheMetrics = this.handleAsync(async (req: ExtendedRequest, res: Response): Promise<void> => {
    // Check if user is authenticated and has admin role
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    // In a real implementation, check if user has admin role
    // For now, we'll just assume they do

    try {
      // In a real implementation, this would query the performance monitoring service
      // For now, we'll just return mock data
      const cacheMetrics = {
        timestamp: new Date(),
        overview: {
          hitRate: 85, // percentage
          missRate: 15, // percentage
          size: 1024, // KB
          maxSize: 2048, // KB
          itemCount: 5000,
          averageTtl: 3600, // seconds
        },
        operations: {
          gets: 10000,
          sets: 2000,
          deletes: 500,
          expirations: 1000,
        },
        keys: {
          byPrefix: [
            {
              prefix: 'session:',
              count: 2000,
              sizeKB: 400,
              hitRate: 90, // percentage
            },
            {
              prefix: 'user:',
              count: 1500,
              sizeKB: 300,
              hitRate: 85, // percentage
            },
            {
              prefix: 'mfa:',
              count: 800,
              sizeKB: 160,
              hitRate: 75, // percentage
            },
            {
              prefix: 'rate-limit:',
              count: 500,
              sizeKB: 100,
              hitRate: 95, // percentage
            },
            {
              prefix: 'config:',
              count: 200,
              sizeKB: 64,
              hitRate: 99, // percentage
            },
          ],
          mostAccessed: [
            {
              key: 'session:active-count',
              accessCount: 5000,
              hitRate: 99, // percentage
              lastAccessed: new Date(Date.now() - 60000), // 1 minute ago
            },
            {
              key: 'config:auth-settings',
              accessCount: 4500,
              hitRate: 99, // percentage
              lastAccessed: new Date(Date.now() - 120000), // 2 minutes ago
            },
            {
              key: 'user:count',
              accessCount: 4000,
              hitRate: 98, // percentage
              lastAccessed: new Date(Date.now() - 180000), // 3 minutes ago
            },
          ],
        },
        memoryUsage: {
          used: 1024, // MB
          peak: 1200, // MB
          fragmentationRatio: 1.2,
        },
      };

      sendOkResponse(res, 'Cache metrics retrieved successfully', cacheMetrics);
    } catch (error) {
      logger.error('Error getting cache metrics', { error, userId: req.user?.id });
      throw error;
    }
  });

  /**
   * Get endpoint performance metrics
   * @route GET /performance/endpoints
   */
  getEndpointMetrics = this.handleAsync(
    async (req: ExtendedRequest, res: Response): Promise<void> => {
      // Check if user is authenticated and has admin role
      if (!req.user) {
        throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
      }

      // In a real implementation, check if user has admin role
      // For now, we'll just assume they do

      try {
        // Get sort parameter from query
        const sort = (req.query['sort'] as string) || 'requests';

        // In a real implementation, this would query the performance monitoring service
        // For now, we'll just return mock data
        const endpoints = [
          {
            path: '/api/auth/login',
            method: 'POST',
            requestCount: 5000,
            averageResponseTime: 60, // ms
            p95ResponseTime: 120, // ms
            p99ResponseTime: 200, // ms
            errorRate: 0.8, // percentage
            successRate: 99.2, // percentage
          },
          {
            path: '/api/auth/refresh',
            method: 'POST',
            requestCount: 4500,
            averageResponseTime: 30, // ms
            p95ResponseTime: 80, // ms
            p99ResponseTime: 150, // ms
            errorRate: 0.2, // percentage
            successRate: 99.8, // percentage
          },
          {
            path: '/api/user/profile',
            method: 'GET',
            requestCount: 3000,
            averageResponseTime: 50, // ms
            p95ResponseTime: 100, // ms
            p99ResponseTime: 180, // ms
            errorRate: 0.3, // percentage
            successRate: 99.7, // percentage
          },
          {
            path: '/api/auth/logout',
            method: 'POST',
            requestCount: 2500,
            averageResponseTime: 25, // ms
            p95ResponseTime: 60, // ms
            p99ResponseTime: 100, // ms
            errorRate: 0.1, // percentage
            successRate: 99.9, // percentage
          },
          {
            path: '/api/mfa/verify',
            method: 'POST',
            requestCount: 2000,
            averageResponseTime: 70, // ms
            p95ResponseTime: 150, // ms
            p99ResponseTime: 250, // ms
            errorRate: 1.2, // percentage
            successRate: 98.8, // percentage
          },
          {
            path: '/api/user/activity-log',
            method: 'GET',
            requestCount: 500,
            averageResponseTime: 250, // ms
            p95ResponseTime: 500, // ms
            p99ResponseTime: 800, // ms
            errorRate: 0.5, // percentage
            successRate: 99.5, // percentage
          },
          {
            path: '/api/compliance/data-export',
            method: 'GET',
            requestCount: 50,
            averageResponseTime: 200, // ms
            p95ResponseTime: 400, // ms
            p99ResponseTime: 600, // ms
            errorRate: 1.0, // percentage
            successRate: 99.0, // percentage
          },
          {
            path: '/api/audit/logs',
            method: 'GET',
            requestCount: 300,
            averageResponseTime: 180, // ms
            p95ResponseTime: 350, // ms
            p99ResponseTime: 500, // ms
            errorRate: 0.7, // percentage
            successRate: 99.3, // percentage
          },
          {
            path: '/api/risk/assessment',
            method: 'GET',
            requestCount: 800,
            averageResponseTime: 150, // ms
            p95ResponseTime: 300, // ms
            p99ResponseTime: 450, // ms
            errorRate: 0.4, // percentage
            successRate: 99.6, // percentage
          },
          {
            path: '/api/mfa/setup',
            method: 'POST',
            requestCount: 600,
            averageResponseTime: 120, // ms
            p95ResponseTime: 250, // ms
            p99ResponseTime: 400, // ms
            errorRate: 0.6, // percentage
            successRate: 99.4, // percentage
          },
        ];

        // Sort endpoints based on query parameter
        let sortedEndpoints = [...endpoints];
        if (sort === 'response_time') {
          sortedEndpoints.sort((a, b) => b.averageResponseTime - a.averageResponseTime);
        } else if (sort === 'error_rate') {
          sortedEndpoints.sort((a, b) => b.errorRate - a.errorRate);
        } else {
          // Default sort by request count
          sortedEndpoints.sort((a, b) => b.requestCount - a.requestCount);
        }

        sendOkResponse(res, 'Endpoint metrics retrieved successfully', sortedEndpoints);
      } catch (error) {
        logger.error('Error getting endpoint metrics', {
          error,
          userId: req.user?.id,
          sort: req.query['sort'],
        });
        throw error;
      }
    }
  );
}

// Create instance
export const performanceController = new PerformanceController();
