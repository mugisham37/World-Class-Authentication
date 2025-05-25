import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  AuditLog,
  AuditStatus,
  CreateAuditLogData,
  AuditLogFilterOptions,
} from '../models/audit-log.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * Audit log repository interface
 * Defines audit log-specific operations
 */
export interface AuditLogRepository extends BaseRepository<AuditLog, string> {
  /**
   * Find audit logs by user ID
   * @param userId The user ID
   * @param limit Maximum number of logs to return (optional)
   * @returns Array of audit logs
   */
  findByUserId(userId: string, limit?: number): Promise<AuditLog[]>;

  /**
   * Find audit logs by action
   * @param action The action
   * @param limit Maximum number of logs to return (optional)
   * @returns Array of audit logs
   */
  findByAction(action: string, limit?: number): Promise<AuditLog[]>;

  /**
   * Find audit logs by entity
   * @param entityType The entity type
   * @param entityId The entity ID
   * @param limit Maximum number of logs to return (optional)
   * @returns Array of audit logs
   */
  findByEntity(entityType: string, entityId: string, limit?: number): Promise<AuditLog[]>;

  /**
   * Find audit logs by IP address
   * @param ipAddress The IP address
   * @param limit Maximum number of logs to return (optional)
   * @returns Array of audit logs
   */
  findByIpAddress(ipAddress: string, limit?: number): Promise<AuditLog[]>;

  /**
   * Find audit logs by status
   * @param status The audit status
   * @param limit Maximum number of logs to return (optional)
   * @returns Array of audit logs
   */
  findByStatus(status: AuditStatus, limit?: number): Promise<AuditLog[]>;

  /**
   * Find audit logs by time range
   * @param startDate The start date
   * @param endDate The end date
   * @param limit Maximum number of logs to return (optional)
   * @returns Array of audit logs
   */
  findByTimeRange(startDate: Date, endDate: Date, limit?: number): Promise<AuditLog[]>;

  /**
   * Delete audit logs older than a specified date
   * @param date The cutoff date
   * @returns Number of deleted audit logs
   */
  deleteOlderThan(date: Date): Promise<number>;

  /**
   * Delete audit logs by user ID
   * @param userId The user ID
   * @returns Number of deleted audit logs
   */
  deleteByUserId(userId: string): Promise<number>;
}

/**
 * Prisma implementation of the audit log repository
 */
export class PrismaAuditLogRepository
  extends PrismaBaseRepository<AuditLog, string>
  implements AuditLogRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'auditLog';

  /**
   * Find audit logs by user ID
   * @param userId The user ID
   * @param limit Maximum number of logs to return (optional)
   * @returns Array of audit logs
   */
  async findByUserId(userId: string, limit?: number): Promise<AuditLog[]> {
    try {
      const logs = await this.prisma.auditLog.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        ...(limit ? { take: limit } : {}),
      });
      return logs;
    } catch (error) {
      logger.error('Error finding audit logs by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding audit logs by user ID',
        'AUDIT_LOG_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find audit logs by action
   * @param action The action
   * @param limit Maximum number of logs to return (optional)
   * @returns Array of audit logs
   */
  async findByAction(action: string, limit?: number): Promise<AuditLog[]> {
    try {
      const logs = await this.prisma.auditLog.findMany({
        where: { action },
        orderBy: { createdAt: 'desc' },
        ...(limit ? { take: limit } : {}),
      });
      return logs;
    } catch (error) {
      logger.error('Error finding audit logs by action', { action, error });
      throw new DatabaseError(
        'Error finding audit logs by action',
        'AUDIT_LOG_FIND_BY_ACTION_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find audit logs by entity
   * @param entityType The entity type
   * @param entityId The entity ID
   * @param limit Maximum number of logs to return (optional)
   * @returns Array of audit logs
   */
  async findByEntity(entityType: string, entityId: string, limit?: number): Promise<AuditLog[]> {
    try {
      const logs = await this.prisma.auditLog.findMany({
        where: {
          entityType,
          entityId,
        },
        orderBy: { createdAt: 'desc' },
        ...(limit ? { take: limit } : {}),
      });
      return logs;
    } catch (error) {
      logger.error('Error finding audit logs by entity', { entityType, entityId, error });
      throw new DatabaseError(
        'Error finding audit logs by entity',
        'AUDIT_LOG_FIND_BY_ENTITY_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find audit logs by IP address
   * @param ipAddress The IP address
   * @param limit Maximum number of logs to return (optional)
   * @returns Array of audit logs
   */
  async findByIpAddress(ipAddress: string, limit?: number): Promise<AuditLog[]> {
    try {
      const logs = await this.prisma.auditLog.findMany({
        where: { ipAddress },
        orderBy: { createdAt: 'desc' },
        ...(limit ? { take: limit } : {}),
      });
      return logs;
    } catch (error) {
      logger.error('Error finding audit logs by IP address', { ipAddress, error });
      throw new DatabaseError(
        'Error finding audit logs by IP address',
        'AUDIT_LOG_FIND_BY_IP_ADDRESS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find audit logs by status
   * @param status The audit status
   * @param limit Maximum number of logs to return (optional)
   * @returns Array of audit logs
   */
  async findByStatus(status: AuditStatus, limit?: number): Promise<AuditLog[]> {
    try {
      const logs = await this.prisma.auditLog.findMany({
        where: { status },
        orderBy: { createdAt: 'desc' },
        ...(limit ? { take: limit } : {}),
      });
      return logs;
    } catch (error) {
      logger.error('Error finding audit logs by status', { status, error });
      throw new DatabaseError(
        'Error finding audit logs by status',
        'AUDIT_LOG_FIND_BY_STATUS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find audit logs by time range
   * @param startDate The start date
   * @param endDate The end date
   * @param limit Maximum number of logs to return (optional)
   * @returns Array of audit logs
   */
  async findByTimeRange(startDate: Date, endDate: Date, limit?: number): Promise<AuditLog[]> {
    try {
      const logs = await this.prisma.auditLog.findMany({
        where: {
          createdAt: {
            gte: startDate,
            lte: endDate,
          },
        },
        orderBy: { createdAt: 'desc' },
        ...(limit ? { take: limit } : {}),
      });
      return logs;
    } catch (error) {
      logger.error('Error finding audit logs by time range', { startDate, endDate, error });
      throw new DatabaseError(
        'Error finding audit logs by time range',
        'AUDIT_LOG_FIND_BY_TIME_RANGE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete audit logs older than a specified date
   * @param date The cutoff date
   * @returns Number of deleted audit logs
   */
  async deleteOlderThan(date: Date): Promise<number> {
    try {
      const result = await this.prisma.auditLog.deleteMany({
        where: {
          createdAt: {
            lt: date,
          },
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting audit logs older than date', { date, error });
      throw new DatabaseError(
        'Error deleting audit logs older than date',
        'AUDIT_LOG_DELETE_OLDER_THAN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete audit logs by user ID
   * @param userId The user ID
   * @returns Number of deleted audit logs
   */
  async deleteByUserId(userId: string): Promise<number> {
    try {
      const result = await this.prisma.auditLog.deleteMany({
        where: { userId },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting audit logs by user ID', { userId, error });
      throw new DatabaseError(
        'Error deleting audit logs by user ID',
        'AUDIT_LOG_DELETE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  protected override toWhereClause(filter?: AuditLogFilterOptions): any {
    if (!filter) {
      return {};
    }

    const where: any = {};

    if (filter.id) {
      where.id = filter.id;
    }

    if (filter.userId) {
      where.userId = filter.userId;
    }

    if (filter.action) {
      where.action = filter.action;
    }

    if (filter.entityType) {
      where.entityType = filter.entityType;
    }

    if (filter.entityId) {
      where.entityId = filter.entityId;
    }

    if (filter.ipAddress) {
      where.ipAddress = filter.ipAddress;
    }

    if (filter.status) {
      where.status = filter.status;
    }

    // Date range filters
    if (filter.createdAtBefore || filter.createdAtAfter) {
      where.createdAt = {};

      if (filter.createdAtBefore) {
        where.createdAt.lte = filter.createdAtBefore;
      }

      if (filter.createdAtAfter) {
        where.createdAt.gte = filter.createdAtAfter;
      }
    }

    return where;
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected override withTransaction(tx: PrismaClient): BaseRepository<AuditLog, string> {
    return new PrismaAuditLogRepository(tx);
  }
}

// Export a singleton instance
export const auditLogRepository = new PrismaAuditLogRepository();
