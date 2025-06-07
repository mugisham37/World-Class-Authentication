import type { Request, Response } from 'express';
import { BaseController } from './base.controller';
import { sendOkResponse } from '../responses';
import { AuthenticationError } from '../../utils/error-handling';
import { logger } from '../../infrastructure/logging/logger';

/**
 * Validates if the provided date range is valid
 * @param startDate - Start date string in ISO format
 * @param endDate - End date string in ISO format
 * @returns boolean indicating if the date range is valid
 */
function isValidDateRange(startDate?: string, endDate?: string): boolean {
  if (!startDate && !endDate) return true;

  const start = startDate ? new Date(startDate) : new Date(0);
  const end = endDate ? new Date(endDate) : new Date();

  return !isNaN(start.getTime()) && !isNaN(end.getTime()) && start <= end;
}

/**
 * Audit controller
 * Handles audit log access and management
 */
export class AuditController extends BaseController {
  /**
   * Get audit logs
   * @route GET /audit/logs
   */
  getAuditLogs = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated and has admin role
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    // In a real implementation, check if user has admin role
    // For now, we'll just assume they do

    try {
      // Get pagination parameters
      const page = parseInt(req.query['page'] as string) || 1;
      const limit = parseInt(req.query['limit'] as string) || 20;

      // Get filter parameters
      const userId = req.query['userId'] as string;
      const actionType = req.query['actionType'] as string;
      const startDate = req.query['startDate'] as string;
      const endDate = req.query['endDate'] as string;
      const resource = req.query['resource'] as string;

      // Validate date range if provided
      if ((startDate || endDate) && !isValidDateRange(startDate, endDate)) {
        throw new Error('Invalid date range');
      }

      // Convert date strings to timestamps for comparison
      const startDateTime = startDate ? new Date(startDate).getTime() : 0;
      const endDateTime = endDate ? new Date(endDate).getTime() : Date.now();

      // In a real implementation, this would query the audit log service
      // For now, we'll just return mock data
      const auditLogs = {
        items: Array.from({ length: limit }, (_, i) => {
          const timestamp = new Date(Date.now() - i * 3600000);

          // Skip if outside date range
          if (timestamp.getTime() < startDateTime || timestamp.getTime() > endDateTime) {
            return null;
          }

          return {
            id: `log_${i}`,
            timestamp,
            userId: userId || `user_${i % 5}`,
            actionType: actionType || (i % 3 === 0 ? 'LOGIN' : i % 3 === 1 ? 'UPDATE' : 'DELETE'),
            resource: resource || (i % 2 === 0 ? 'user' : 'session'),
            resourceId: `resource_${i}`,
            ipAddress: '127.0.0.1',
            userAgent: 'Mozilla/5.0',
            metadata: {
              success: i % 4 !== 0,
              details: `Operation ${i % 4 !== 0 ? 'succeeded' : 'failed'}`,
            },
          };
        }).filter(Boolean), // Remove null entries
        pagination: {
          page,
          limit,
          totalItems: 100,
          totalPages: Math.ceil(100 / limit),
        },
      };

      sendOkResponse(res, 'Audit logs retrieved successfully', auditLogs);
    } catch (error) {
      logger.error('Error getting audit logs', { error, userId: req.user.id });
      throw error;
    }
  });

  /**
   * Get audit log by ID
   * @route GET /audit/logs/:id
   */
  getAuditLogById = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated and has admin role
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    // In a real implementation, check if user has admin role
    // For now, we'll just assume they do

    try {
      const { id } = req.params;

      // In a real implementation, this would query the audit log service
      // For now, we'll just return mock data
      const auditLog = {
        id,
        timestamp: new Date(),
        userId: 'user_123',
        actionType: 'LOGIN',
        resource: 'user',
        resourceId: 'resource_456',
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0',
        metadata: {
          success: true,
          details: 'Login successful',
        },
      };

      sendOkResponse(res, 'Audit log retrieved successfully', auditLog);
    } catch (error) {
      logger.error('Error getting audit log by ID', {
        error,
        logId: req.params['id'],
        userId: req.user.id,
      });
      throw error;
    }
  });

  /**
   * Get user activity audit logs
   * @route GET /audit/users/:userId/activity
   */
  getUserActivityLogs = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    try {
      const { userId } = req.params;

      // Check if user is requesting their own logs or has admin role
      if (userId !== req.user.id) {
        // In a real implementation, check if user has admin role
        // For now, we'll just assume they don't
        throw new AuthenticationError("Unauthorized to access other users' logs", 'UNAUTHORIZED');
      }

      // Get pagination parameters
      const page = parseInt(req.query['page'] as string) || 1;
      const limit = parseInt(req.query['limit'] as string) || 20;

      // Get filter parameters
      const actionType = req.query['actionType'] as string;
      const startDate = req.query['startDate'] as string;
      const endDate = req.query['endDate'] as string;

      // Validate date range if provided
      if ((startDate || endDate) && !isValidDateRange(startDate, endDate)) {
        throw new Error('Invalid date range');
      }

      // Convert date strings to timestamps for comparison
      const startDateTime = startDate ? new Date(startDate).getTime() : 0;
      const endDateTime = endDate ? new Date(endDate).getTime() : Date.now();

      // In a real implementation, this would query the audit log service
      // For now, we'll just return mock data
      const activityLogs = {
        items: Array.from({ length: limit }, (_, i) => {
          const timestamp = new Date(Date.now() - i * 3600000);

          // Skip if outside date range
          if (timestamp.getTime() < startDateTime || timestamp.getTime() > endDateTime) {
            return null;
          }

          return {
            id: `log_${i}`,
            timestamp,
            actionType:
              actionType ||
              (i % 3 === 0 ? 'LOGIN' : i % 3 === 1 ? 'PROFILE_UPDATE' : 'PASSWORD_CHANGE'),
            ipAddress: '127.0.0.1',
            userAgent: 'Mozilla/5.0',
            location: 'New York, USA',
            deviceInfo: {
              type: i % 2 === 0 ? 'desktop' : 'mobile',
              os: i % 2 === 0 ? 'Windows 10' : 'iOS 15',
              browser: i % 2 === 0 ? 'Chrome 98' : 'Safari 15',
            },
            success: i % 4 !== 0,
          };
        }).filter(Boolean), // Remove null entries
        pagination: {
          page,
          limit,
          totalItems: 100,
          totalPages: Math.ceil(100 / limit),
        },
      };

      sendOkResponse(res, 'User activity logs retrieved successfully', activityLogs);
    } catch (error) {
      logger.error('Error getting user activity logs', {
        error,
        userId: req.params['userId'],
        requesterId: req.user.id,
      });
      throw error;
    }
  });

  /**
   * Get security events
   * @route GET /audit/security-events
   */
  getSecurityEvents = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated and has admin role
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    // In a real implementation, check if user has admin role
    // For now, we'll just assume they do

    try {
      // Get pagination parameters
      const page = parseInt(req.query['page'] as string) || 1;
      const limit = parseInt(req.query['limit'] as string) || 20;

      // Get filter parameters
      const severity = req.query['severity'] as string;
      const eventType = req.query['eventType'] as string;
      const startDate = req.query['startDate'] as string;
      const endDate = req.query['endDate'] as string;

      // Validate date range if provided
      if ((startDate || endDate) && !isValidDateRange(startDate, endDate)) {
        throw new Error('Invalid date range');
      }

      // Convert date strings to timestamps for comparison
      const startDateTime = startDate ? new Date(startDate).getTime() : 0;
      const endDateTime = endDate ? new Date(endDate).getTime() : Date.now();

      // In a real implementation, this would query the audit log service
      // For now, we'll just return mock data
      const securityEvents = {
        items: Array.from({ length: limit }, (_, i) => {
          const timestamp = new Date(Date.now() - i * 3600000);

          // Skip if outside date range
          if (timestamp.getTime() < startDateTime || timestamp.getTime() > endDateTime) {
            return null;
          }

          return {
            id: `event_${i}`,
            timestamp,
            eventType:
              eventType ||
              (i % 4 === 0
                ? 'FAILED_LOGIN_ATTEMPT'
                : i % 4 === 1
                  ? 'SUSPICIOUS_ACTIVITY'
                  : i % 4 === 2
                    ? 'PASSWORD_RESET'
                    : 'ROLE_CHANGE'),
            severity: severity || (i % 3 === 0 ? 'HIGH' : i % 3 === 1 ? 'MEDIUM' : 'LOW'),
            userId: `user_${i % 5}`,
            ipAddress: '127.0.0.1',
            userAgent: 'Mozilla/5.0',
            location: 'New York, USA',
            details: `Security event details for event ${i}`,
            mitigationStatus: i % 2 === 0 ? 'RESOLVED' : 'PENDING',
          };
        }).filter(Boolean), // Remove null entries
        pagination: {
          page,
          limit,
          totalItems: 100,
          totalPages: Math.ceil(100 / limit),
        },
      };

      sendOkResponse(res, 'Security events retrieved successfully', securityEvents);
    } catch (error) {
      logger.error('Error getting security events', { error, userId: req.user.id });
      throw error;
    }
  });

  /**
   * Export audit logs
   * @route GET /audit/export
   */
  exportAuditLogs = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated and has admin role
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    // In a real implementation, check if user has admin role
    // For now, we'll just assume they do

    try {
      // Get filter parameters
      const userId = req.query['userId'] as string;
      const actionType = req.query['actionType'] as string;
      const startDate = req.query['startDate'] as string;
      const endDate = req.query['endDate'] as string;
      const resource = req.query['resource'] as string;
      const format = (req.query['format'] as string) || 'json';

      // Validate date range if provided
      if ((startDate || endDate) && !isValidDateRange(startDate, endDate)) {
        throw new Error('Invalid date range');
      }

      // Convert date strings to timestamps for comparison
      const startDateTime = startDate ? new Date(startDate).getTime() : 0;
      const endDateTime = endDate ? new Date(endDate).getTime() : Date.now();

      // In a real implementation, this would query the audit log service
      // For now, we'll just return mock data
      const auditLogs = Array.from({ length: 100 }, (_, i) => {
        const timestamp = new Date(Date.now() - i * 3600000);

        // Skip if outside date range
        if (timestamp.getTime() < startDateTime || timestamp.getTime() > endDateTime) {
          return null;
        }

        return {
          id: `log_${i}`,
          timestamp,
          userId: userId || `user_${i % 5}`,
          actionType: actionType || (i % 3 === 0 ? 'LOGIN' : i % 3 === 1 ? 'UPDATE' : 'DELETE'),
          resource: resource || (i % 2 === 0 ? 'user' : 'session'),
          resourceId: `resource_${i}`,
          ipAddress: '127.0.0.1',
          userAgent: 'Mozilla/5.0',
          metadata: {
            success: i % 4 !== 0,
            details: `Operation ${i % 4 !== 0 ? 'succeeded' : 'failed'}`,
          },
        };
      }).filter(Boolean); // Remove null entries

      // Format data based on requested format
      let exportData: string;
      if (format === 'csv') {
        // Generate CSV
        const headers = 'id,timestamp,userId,actionType,resource,resourceId,ipAddress,success\n';
        // We've already filtered out null values with filter(Boolean), so we can safely assert the type
        const rows = auditLogs
          .map(
            log =>
              `${log!.id},${log!.timestamp.toISOString()},${log!.userId},${log!.actionType},${log!.resource},${log!.resourceId},${log!.ipAddress},${log!.metadata.success}`
          )
          .join('\n');
        exportData = headers + rows;

        // Set headers
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=audit-logs.csv');
      } else {
        // Default to JSON
        exportData = JSON.stringify(auditLogs, null, 2);

        // Set headers
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', 'attachment; filename=audit-logs.json');
      }

      // Send data
      res.status(200).send(exportData);
    } catch (error) {
      logger.error('Error exporting audit logs', { error, userId: req.user.id });
      throw error;
    }
  });
}

// Create instance
export const auditController = new AuditController();
