import { Prisma, PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import { AuditLog, AuditStatus, AuditLogFilterOptions } from '../models/audit-log.model';
import { AuditStatus as CoreAuditStatus } from '../../core/audit/types';
// import { CreateData } from './base.repository';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * Audit search options interface
 * Defines options for searching audit logs
 */
export interface AuditSearchOptions {
  skip?: number;
  limit?: number;
  startDate?: Date;
  endDate?: Date;
  userId?: string;
  actions?: string[];
  entityTypes?: string[];
  entityIds?: string[];
  severity?: string[];
  status?: CoreAuditStatus[];
  ipAddress?: string;
  query?: string;
}

/**
 * Audit search result interface
 * Defines the structure of search results
 */
export interface AuditSearchResult {
  logs: AuditLog[];
  total: number;
}

/**
 * Audit statistics options interface
 * Defines options for retrieving audit statistics
 */
export interface AuditStatisticsOptions {
  startDate?: Date;
  endDate?: Date;
  userId?: string;
  groupBy?: 'action' | 'entityType' | 'severity' | 'status' | 'hour' | 'day' | 'week' | 'month';
}

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

  /**
   * Search audit logs with advanced filtering
   * @param options Search options
   * @returns Search results with logs and total count
   */
  search(options: AuditSearchOptions): Promise<AuditSearchResult>;

  /**
   * Get audit log statistics
   * @param options Statistics options
   * @returns Statistics as key-value pairs
   */
  getStatistics(options: AuditStatisticsOptions): Promise<Record<string, number>>;

  /**
   * Anonymize audit logs by user ID
   * @param userId User ID
   * @returns Void promise
   */
  anonymizeByUserId(userId: string): Promise<void>;
}

/**
 * Maps a Prisma AuditLog to the domain AuditLog model
 * @param prismaAuditLog The Prisma AuditLog entity
 * @returns The domain AuditLog model
 */
function mapToDomainModel(prismaAuditLog: {
  id: string;
  createdAt: Date;
  userId: string | null;
  action: string;
  entityType: string | null;
  entityId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: Prisma.JsonValue | null;
  status: any;
}): AuditLog {
  return {
    id: prismaAuditLog.id,
    createdAt: prismaAuditLog.createdAt,
    userId: prismaAuditLog.userId,
    action: prismaAuditLog.action,
    entityType: prismaAuditLog.entityType,
    entityId: prismaAuditLog.entityId,
    ipAddress: prismaAuditLog.ipAddress,
    userAgent: prismaAuditLog.userAgent,
    // Convert JsonValue to Record<string, any> | null
    metadata: prismaAuditLog.metadata
      ? typeof prismaAuditLog.metadata === 'object'
        ? (prismaAuditLog.metadata as Record<string, any>)
        : null
      : null,
    status: prismaAuditLog.status as AuditStatus,
  };
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
   * Find an audit log by ID
   * @param id The audit log ID
   * @returns The audit log or null if not found
   */
  public override async findById(id: string): Promise<AuditLog | null> {
    try {
      const log = await this.prisma.auditLog.findUnique({
        where: { id },
      });
      return log ? mapToDomainModel(log) : null;
    } catch (error) {
      logger.error('Error finding audit log by ID', { id, error });
      throw new DatabaseError(
        'Error finding audit log by ID',
        'AUDIT_LOG_FIND_BY_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find audit logs by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns List of audit logs
   */
  public async findByUserId(userId: string, options?: AuditLogFilterOptions): Promise<AuditLog[]> {
    try {
      const where = this.buildWhereClause({ ...options, userId });
      const logs = await this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return logs.map(mapToDomainModel);
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
  public async findByAction(action: string, options?: AuditLogFilterOptions): Promise<AuditLog[]> {
    try {
      const where = this.buildWhereClause({ ...options, action });
      const logs = await this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return logs.map(mapToDomainModel);
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
  public async findByEntity(
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
      return logs.map(mapToDomainModel);
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
  public async findByIpAddress(
    ipAddress: string,
    options?: AuditLogFilterOptions
  ): Promise<AuditLog[]> {
    try {
      const where = this.buildWhereClause({ ...options, ipAddress });
      const logs = await this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return logs.map(mapToDomainModel);
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
  public async findByStatus(
    status: AuditStatus,
    options?: AuditLogFilterOptions
  ): Promise<AuditLog[]> {
    try {
      const where = this.buildWhereClause({ ...options, status });
      const logs = await this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return logs.map(mapToDomainModel);
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
  public async findByTimeRange(
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
      return logs.map(mapToDomainModel);
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
  public async countByUserId(userId: string, options?: AuditLogFilterOptions): Promise<number> {
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
  public async countByAction(action: string, options?: AuditLogFilterOptions): Promise<number> {
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
  public async countByStatus(
    status: AuditStatus,
    options?: AuditLogFilterOptions
  ): Promise<number> {
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
  public async deleteOlderThan(date: Date): Promise<number> {
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
  public async deleteByUserId(userId: string, options?: AuditLogFilterOptions): Promise<number> {
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
   * Search audit logs with advanced filtering
   * @param options Search options
   * @returns Search results with logs and total count
   */
  public async search(options: AuditSearchOptions): Promise<AuditSearchResult> {
    try {
      const where: any = {};

      // Apply filters
      if (options.userId) {
        where.userId = options.userId;
      }

      if (options.actions && options.actions.length > 0) {
        where.action = { in: options.actions };
      }

      if (options.entityTypes && options.entityTypes.length > 0) {
        where.entityType = { in: options.entityTypes };
      }

      if (options.entityIds && options.entityIds.length > 0) {
        where.entityId = { in: options.entityIds };
      }

      if (options.severity && options.severity.length > 0) {
        where.severity = { in: options.severity };
      }

      if (options.status && options.status.length > 0) {
        where.status = { in: options.status };
      }

      if (options.ipAddress) {
        where.ipAddress = options.ipAddress;
      }

      // Date range filters
      if (options.startDate || options.endDate) {
        where.createdAt = {};

        if (options.startDate) {
          where.createdAt.gte = options.startDate;
        }

        if (options.endDate) {
          where.createdAt.lte = options.endDate;
        }
      }

      // Text search
      if (options.query) {
        where.OR = [
          { action: { contains: options.query, mode: 'insensitive' } },
          { entityType: { contains: options.query, mode: 'insensitive' } },
          { entityId: { contains: options.query, mode: 'insensitive' } },
          { ipAddress: { contains: options.query, mode: 'insensitive' } },
          { userAgent: { contains: options.query, mode: 'insensitive' } },
        ];
      }

      // Get total count
      const total = await this.prisma.auditLog.count({ where });

      // Get logs with pagination
      const logs = await this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: options.skip || 0,
        take: options.limit || 20,
      });

      return {
        logs: logs.map(mapToDomainModel),
        total,
      };
    } catch (error) {
      logger.error('Error searching audit logs', { options, error });
      throw new DatabaseError(
        'Error searching audit logs',
        'AUDIT_LOG_SEARCH_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Get audit log statistics
   * @param options Statistics options
   * @returns Statistics as key-value pairs
   */
  public async getStatistics(options: AuditStatisticsOptions): Promise<Record<string, number>> {
    try {
      const where: any = {};

      // Apply filters
      if (options.userId) {
        where.userId = options.userId;
      }

      // Date range filters
      if (options.startDate || options.endDate) {
        where.createdAt = {};

        if (options.startDate) {
          where.createdAt.gte = options.startDate;
        }

        if (options.endDate) {
          where.createdAt.lte = options.endDate;
        }
      }

      // Group by different fields
      const groupBy = options.groupBy || 'action';
      let result: Record<string, number> = {};

      switch (groupBy) {
        case 'action':
          const actionStats = await this.prisma.auditLog.groupBy({
            by: ['action'],
            where,
            _count: true,
          });
          result = actionStats.reduce(
            (acc: Record<string, number>, curr: { action: string; _count: number }) => {
              acc[curr.action] = curr._count;
              return acc;
            },
            {} as Record<string, number>
          );
          break;

        case 'entityType':
          const entityTypeStats = await this.prisma.auditLog.groupBy({
            by: ['entityType'],
            where,
            _count: true,
          });
          result = entityTypeStats.reduce(
            (acc: Record<string, number>, curr: { entityType: string | null; _count: number }) => {
              acc[curr.entityType || 'unknown'] = curr._count;
              return acc;
            },
            {} as Record<string, number>
          );
          break;

        // Severity might not be in the Prisma schema, so we'll handle it differently
        case 'severity':
          // Since severity might not be in the schema, we'll use a different approach
          const severityLogs = await this.prisma.auditLog.findMany({
            where,
            select: {
              id: true,
              // Add any field that might contain severity information
              // For example, it might be stored in metadata
              metadata: true,
            },
          });

          // Process logs to extract severity information
          // This is a placeholder implementation - adjust based on your actual data structure
          result = severityLogs.reduce(
            (
              acc: Record<string, number>,
              log: { id: string; metadata: Prisma.JsonValue | null }
            ) => {
              // Assuming severity might be stored in metadata
              const severity =
                log.metadata && typeof log.metadata === 'object'
                  ? (log.metadata as any).severity || 'unknown'
                  : 'unknown';

              acc[severity] = (acc[severity] || 0) + 1;
              return acc;
            },
            {} as Record<string, number>
          );
          break;

        case 'status':
          const statusStats = await this.prisma.auditLog.groupBy({
            by: ['status'],
            where,
            _count: true,
          });
          result = statusStats.reduce(
            (acc: Record<string, number>, curr: { status: string; _count: number }) => {
              acc[curr.status] = curr._count;
              return acc;
            },
            {} as Record<string, number>
          );
          break;

        case 'hour':
        case 'day':
        case 'week':
        case 'month':
          // For time-based grouping, we would use raw SQL or a more complex query
          // This is a simplified implementation
          const timeLogs = await this.prisma.auditLog.findMany({
            where,
            select: { createdAt: true },
            orderBy: { createdAt: 'asc' },
          });

          result = timeLogs.reduce(
            (acc: Record<string, number>, log: { createdAt: Date }) => {
              let key: string;
              const date = log.createdAt;

              if (groupBy === 'hour') {
                key = `${date.getFullYear()}-${date.getMonth() + 1}-${date.getDate()} ${date.getHours()}:00`;
              } else if (groupBy === 'day') {
                key = `${date.getFullYear()}-${date.getMonth() + 1}-${date.getDate()}`;
              } else if (groupBy === 'week') {
                // Get the first day of the week
                const firstDay = new Date(date);
                const day = date.getDay();
                const diff = date.getDate() - day + (day === 0 ? -6 : 1); // Adjust for Sunday
                firstDay.setDate(diff);
                key = `Week of ${firstDay.getFullYear()}-${firstDay.getMonth() + 1}-${firstDay.getDate()}`;
              } else {
                // month
                key = `${date.getFullYear()}-${date.getMonth() + 1}`;
              }

              acc[key] = (acc[key] || 0) + 1;
              return acc;
            },
            {} as Record<string, number>
          );
          break;
      }

      return result;
    } catch (error) {
      logger.error('Error getting audit log statistics', { options, error });
      throw new DatabaseError(
        'Error getting audit log statistics',
        'AUDIT_LOG_STATISTICS_ERROR',
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
  /**
   * Anonymize audit logs by user ID
   * @param userId User ID
   * @returns Void promise
   */
  public async anonymizeByUserId(userId: string): Promise<void> {
    try {
      await this.prisma.auditLog.updateMany({
        where: { userId },
        data: {
          ipAddress: null,
          userAgent: null,
          metadata: {},
        },
      });
    } catch (error) {
      logger.error('Error anonymizing audit logs by user ID', { userId, error });
      throw new DatabaseError(
        'Error anonymizing audit logs by user ID',
        'AUDIT_LOG_ANONYMIZE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  public override withTransaction(tx: PrismaClient): BaseRepository<AuditLog, string> {
    return new PrismaAuditLogRepository(tx);
  }
}

// Export a singleton instance
export const auditLogRepository = new PrismaAuditLogRepository();
