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
import { prisma } from '../prisma/client';

/**
 * Audit log repository interface
 * Defines audit log-specific operations
 */
export interface AuditLogRepository extends BaseRepository<AuditLog, string> {
  /**
   * Find audit logs by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns List of audit logs
   */
  findByUserId(userId: string, options?: AuditLogFilterOptions): Promise<AuditLog[]>;

  /**
   * Find audit logs by action
   * @param action Action
   * @param options Filter options
   * @returns List of audit logs
   */
  findByAction(action: string, options?: AuditLogFilterOptions): Promise<AuditLog[]>;

  /**
   * Find audit logs by entity type and ID
   * @param entityType Entity type
   * @param entityId Entity ID
   * @param options Filter options
   * @returns List of audit logs
   */
  findByEntity(
    entityType: string,
    entityId: string,
    options?: AuditLogFilterOptions
  ): Promise<AuditLog[]>;

  /**
   * Find audit logs by IP address
   * @param ipAddress IP address
   * @param options Filter options
   * @returns List of audit logs
   */
  findByIpAddress(ipAddress: string, options?: AuditLogFilterOptions): Promise<AuditLog[]>;

  /**
   * Find audit logs by status
   * @param status Audit status
   * @param options Filter options
   * @returns List of audit logs
   */
  findByStatus(status: AuditStatus, options?: AuditLogFilterOptions): Promise<AuditLog[]>;

  /**
   * Find audit logs by time range
   * @param startDate Start date
   * @param endDate End date
   * @param options Filter options
   * @returns List of audit logs
   */
  findByTimeRange(
    startDate: Date,
    endDate: Date,
    options?: AuditLogFilterOptions
  ): Promise<AuditLog[]>;

  /**
   * Count audit logs by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns Number of audit logs
   */
  countByUserId(userId: string, options?: AuditLogFilterOptions): Promise<number>;

  /**
   * Count audit logs by action
   * @param action Action
   * @param options Filter options
   * @returns Number of audit logs
   */
  countByAction(action: string, options?: AuditLogFilterOptions): Promise<number>;

  /**
   * Count audit logs by status
   * @param status Audit status
   * @param options Filter options
   * @returns Number of audit logs
   */
  countByStatus(status: AuditStatus, options?: AuditLogFilterOptions): Promise<number>;

  /**
   * Delete audit logs older than a specified date
   * @param date Date threshold
   * @returns Number of deleted audit logs
   */
  deleteOlderThan(date: Date): Promise<number>;

  /**
   * Delete audit logs by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns Number of deleted audit logs
   */
  deleteByUserId(userId: string, options?: AuditLogFilterOptions): Promise<number>;
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
   * @param userId User ID
   * @param options Filter options
   * @returns List of audit logs
   */
  async findByUserId(userId: string, options?: AuditLogFilterOptions): Promise<AuditLog[]> {
    try {
      const where = this.buildWhereClause({ ...options, userId });
      const logs = await this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return logs;
    } catch (error) {
      logger.error('Error finding audit logs by user ID', { userId, options, error });
      throw new DatabaseError(
        'Error finding audit logs by user ID',
        'AUDIT_LOG_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find audit logs by action
   * @param action Action
   * @param options Filter options
   * @returns List of audit logs
   */
  async findByAction(action: string, options?: AuditLogFilterOptions): Promise<AuditLog[]> {
    try {
      const where = this.buildWhereClause({ ...options, action });
      const logs = await this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return logs;
    } catch (error) {
      logger.error('Error finding audit logs by action', { action, options, error });
      throw new DatabaseError(
        'Error finding audit logs by action',
        'AUDIT_LOG_FIND_BY_ACTION_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find audit logs by entity type and ID
   * @param entityType Entity type
   * @param entityId Entity ID
   * @param options Filter options
   * @returns List of audit logs
   */
  async findByEntity(
    entityType: string,
    entityId: string,
    options?: AuditLogFilterOptions
  ): Promise<AuditLog[]> {
    try {
      const where = this.buildWhereClause({ ...options, entityType, entityId });
      const logs = await this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return logs;
    } catch (error) {
      logger.error('Error finding audit logs by entity', { entityType, entityId, options, error });
      throw new DatabaseError(
        'Error finding audit logs by entity',
        'AUDIT_LOG_FIND_BY_ENTITY_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find audit logs by IP address
   * @param ipAddress IP address
   * @param options Filter options
   * @returns List of audit logs
   */
  async findByIpAddress(ipAddress: string, options?: AuditLogFilterOptions): Promise<AuditLog[]> {
    try {
      const where = this.buildWhereClause({ ...options, ipAddress });
      const logs = await this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return logs;
    } catch (error) {
      logger.error('Error finding audit logs by IP address', { ipAddress, options, error });
      throw new DatabaseError(
        'Error finding audit logs by IP address',
        'AUDIT_LOG_FIND_BY_IP_ADDRESS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find audit logs by status
   * @param status Audit status
   * @param options Filter options
   * @returns List of audit logs
   */
  async findByStatus(status: AuditStatus, options?: AuditLogFilterOptions): Promise<AuditLog[]> {
    try {
      const where = this.buildWhereClause({ ...options, status });
      const logs = await this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return logs;
    } catch (error) {
      logger.error('Error finding audit logs by status', { status, options, error });
      throw new DatabaseError(
        'Error finding audit logs by status',
        'AUDIT_LOG_FIND_BY_STATUS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find audit logs by time range
   * @param startDate Start date
   * @param endDate End date
   * @param options Filter options
   * @returns List of audit logs
   */
  async findByTimeRange(
    startDate: Date,
    endDate: Date,
    options?: AuditLogFilterOptions
  ): Promise<AuditLog[]> {
    try {
      const where = this.buildWhereClause({
        ...options,
        createdAtAfter: startDate,
        createdAtBefore: endDate,
      });
      const logs = await this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return logs;
    } catch (error) {
      logger.error('Error finding audit logs by time range', {
        startDate,
        endDate,
        options,
        error,
      });
      throw new DatabaseError(
        'Error finding audit logs by time range',
        'AUDIT_LOG_FIND_BY_TIME_RANGE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count audit logs by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns Number of audit logs
   */
  async countByUserId(userId: string, options?: AuditLogFilterOptions): Promise<number> {
    try {
      const where = this.buildWhereClause({ ...options, userId });
      const count = await this.prisma.auditLog.count({
        where,
      });
      return count;
    } catch (error) {
      logger.error('Error counting audit logs by user ID', { userId, options, error });
      throw new DatabaseError(
        'Error counting audit logs by user ID',
        'AUDIT_LOG_COUNT_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count audit logs by action
   * @param action Action
   * @param options Filter options
   * @returns Number of audit logs
   */
  async countByAction(action: string, options?: AuditLogFilterOptions): Promise<number> {
    try {
      const where = this.buildWhereClause({ ...options, action });
      const count = await this.prisma.auditLog.count({
        where,
      });
      return count;
    } catch (error) {
      logger.error('Error counting audit logs by action', { action, options, error });
      throw new DatabaseError(
        'Error counting audit logs by action',
        'AUDIT_LOG_COUNT_BY_ACTION_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count audit logs by status
   * @param status Audit status
   * @param options Filter options
   * @returns Number of audit logs
   */
  async countByStatus(status: AuditStatus, options?: AuditLogFilterOptions): Promise<number> {
    try {
      const where = this.buildWhereClause({ ...options, status });
      const count = await this.prisma.auditLog.count({
        where,
      });
      return count;
    } catch (error) {
      logger.error('Error counting audit logs by status', { status, options, error });
      throw new DatabaseError(
        'Error counting audit logs by status',
        'AUDIT_LOG_COUNT_BY_STATUS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete audit logs older than a specified date
   * @param date Date threshold
   * @returns Number of deleted audit logs
   */
  async deleteOlderThan(date: Date): Promise<number> {
    try {
      const result = await this.prisma.auditLog.deleteMany({
        where: {
          createdAt: { lt: date },
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
   * @param userId User ID
   * @param options Filter options
   * @returns Number of deleted audit logs
   */
  async deleteByUserId(userId: string, options?: AuditLogFilterOptions): Promise<number> {
    try {
      const where = this.buildWhereClause({ ...options, userId });
      const result = await this.prisma.auditLog.deleteMany({
        where,
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting audit logs by user ID', { userId, options, error });
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
  private buildWhereClause(filter?: AuditLogFilterOptions): any {
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
  protected withTransaction(tx: PrismaClient): BaseRepository<AuditLog, string> {
    return new PrismaAuditLogRepository(tx);
  }
}

// Export a singleton instance
export const auditLogRepository = new PrismaAuditLogRepository();
