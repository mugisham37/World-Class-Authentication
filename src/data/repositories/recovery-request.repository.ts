import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  RecoveryRequest,
  RecoveryRequestType,
  RecoveryRequestStatus,
  RecoveryRequestFilterOptions,
  RecoveryRequestWithApprovals,
  AdminApproval,
  AdminApprovalStatus,
} from '../models/recovery-request.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * Recovery request repository interface
 * Defines recovery request-specific operations
 */
export interface RecoveryRequestRepository extends BaseRepository<RecoveryRequest, string> {
  /**
   * Find recovery requests by user ID
   * @param userId The user ID
   * @returns Array of recovery requests
   */
  findByUserId(userId: string): Promise<RecoveryRequest[]>;

  /**
   * Find pending recovery requests by user ID
   * @param userId The user ID
   * @returns Array of pending recovery requests
   */
  findPendingByUserId(userId: string): Promise<RecoveryRequest[]>;

  /**
   * Find active recovery requests by user ID
   * @param userId The user ID
   * @returns Array of active recovery requests
   */
  findActiveByUserId(userId: string): Promise<RecoveryRequest[]>;

  /**
   * Find recent recovery requests by user ID within a cooldown period
   * @param userId The user ID
   * @param cooldownPeriod The cooldown period in seconds
   * @returns Array of recent recovery requests
   */
  findRecentByUserId(userId: string, cooldownPeriod: number): Promise<RecoveryRequest[]>;

  /**
   * Find recovery requests by user ID and type
   * @param userId The user ID
   * @param type The recovery request type
   * @returns Array of recovery requests
   */
  findByUserIdAndType(userId: string, type: RecoveryRequestType): Promise<RecoveryRequest[]>;

  /**
   * Find recovery requests by status
   * @param status The recovery request status
   * @returns Array of recovery requests
   */
  findByStatus(status: RecoveryRequestStatus): Promise<RecoveryRequest[]>;

  /**
   * Find a recovery request with its admin approvals
   * @param id The recovery request ID
   * @returns The recovery request with approvals or null if not found
   */
  findWithApprovals(id: string): Promise<RecoveryRequestWithApprovals | null>;

  /**
   * Update a recovery request's status
   * @param id The recovery request ID
   * @param status The new status
   * @param completedAt The completion date (if applicable)
   * @returns The updated recovery request
   */
  updateStatus(
    id: string,
    status: RecoveryRequestStatus,
    completedAt?: Date | null
  ): Promise<RecoveryRequest>;

  /**
   * Complete a recovery request
   * @param id The recovery request ID
   * @returns The updated recovery request
   */
  complete(id: string): Promise<RecoveryRequest>;

  /**
   * Cancel a recovery request
   * @param id The recovery request ID
   * @returns The updated recovery request
   */
  cancel(id: string): Promise<RecoveryRequest>;

  /**
   * Expire outdated pending recovery requests
   * @param olderThan Expire requests older than this date
   * @returns Number of expired recovery requests
   */
  expireOutdated(olderThan: Date): Promise<number>;

  /**
   * Count recovery requests by user ID
   * @param userId The user ID
   * @returns Number of recovery requests
   */
  countByUserId(userId: string): Promise<number>;

  /**
   * Count recovery requests by status
   * @param status The recovery request status
   * @returns Number of recovery requests
   */
  countByStatus(status: RecoveryRequestStatus): Promise<number>;
}

/**
 * Prisma implementation of the recovery request repository
 */
export class PrismaRecoveryRequestRepository
  extends PrismaBaseRepository<RecoveryRequest, string>
  implements RecoveryRequestRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'recoveryRequest';

  /**
   * Map Prisma record to model
   * @param prismaRecord The Prisma record
   * @returns The model
   */
  protected mapToModel(prismaRecord: any): RecoveryRequest {
    return {
      ...prismaRecord,
      type: prismaRecord.type as RecoveryRequestType,
      status: prismaRecord.status as RecoveryRequestStatus,
      metadata: prismaRecord.metadata || null,
    };
  }

  /**
   * Map Prisma records to models
   * @param prismaRecords The Prisma records
   * @returns The models
   */
  protected mapToModels(prismaRecords: any[]): RecoveryRequest[] {
    return prismaRecords.map(record => this.mapToModel(record));
  }

  /**
   * Map admin approvals from Prisma to model
   * @param adminApprovals The admin approvals from Prisma
   * @returns The mapped admin approvals
   */
  protected mapAdminApprovals(adminApprovals: any[]): AdminApproval[] {
    return adminApprovals.map(approval => ({
      ...approval,
      status: approval.status as AdminApprovalStatus,
    }));
  }

  /**
   * Find recovery requests by user ID
   * @param userId The user ID
   * @returns Array of recovery requests
   */
  async findByUserId(userId: string): Promise<RecoveryRequest[]> {
    try {
      const requests = await this.prisma.recoveryRequest.findMany({
        where: { userId },
        orderBy: { initiatedAt: 'desc' },
      });
      return this.mapToModels(requests);
    } catch (error) {
      logger.error('Error finding recovery requests by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding recovery requests by user ID',
        'RECOVERY_REQUEST_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find pending recovery requests by user ID
   * @param userId The user ID
   * @returns Array of pending recovery requests
   */
  async findPendingByUserId(userId: string): Promise<RecoveryRequest[]> {
    try {
      const requests = await this.prisma.recoveryRequest.findMany({
        where: {
          userId,
          status: RecoveryRequestStatus.PENDING,
        },
        orderBy: { initiatedAt: 'desc' },
      });
      return this.mapToModels(requests);
    } catch (error) {
      logger.error('Error finding pending recovery requests by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding pending recovery requests by user ID',
        'RECOVERY_REQUEST_FIND_PENDING_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find active recovery requests by user ID
   * @param userId The user ID
   * @returns Array of active recovery requests
   */
  async findActiveByUserId(userId: string): Promise<RecoveryRequest[]> {
    try {
      const requests = await this.prisma.recoveryRequest.findMany({
        where: {
          userId,
          status: RecoveryRequestStatus.PENDING,
        },
        orderBy: { initiatedAt: 'desc' },
      });
      return this.mapToModels(requests);
    } catch (error) {
      logger.error('Error finding active recovery requests by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding active recovery requests by user ID',
        'RECOVERY_REQUEST_FIND_ACTIVE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find recent recovery requests by user ID within a cooldown period
   * @param userId The user ID
   * @param cooldownPeriod The cooldown period in seconds
   * @returns Array of recent recovery requests
   */
  async findRecentByUserId(userId: string, cooldownPeriod: number): Promise<RecoveryRequest[]> {
    try {
      const cutoffDate = new Date(Date.now() - cooldownPeriod * 1000);
      const requests = await this.prisma.recoveryRequest.findMany({
        where: {
          userId,
          initiatedAt: {
            gte: cutoffDate,
          },
        },
        orderBy: { initiatedAt: 'desc' },
      });
      return this.mapToModels(requests);
    } catch (error) {
      logger.error('Error finding recent recovery requests by user ID', {
        userId,
        cooldownPeriod,
        error,
      });
      throw new DatabaseError(
        'Error finding recent recovery requests by user ID',
        'RECOVERY_REQUEST_FIND_RECENT_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find recovery requests by user ID and type
   * @param userId The user ID
   * @param type The recovery request type
   * @returns Array of recovery requests
   */
  async findByUserIdAndType(userId: string, type: RecoveryRequestType): Promise<RecoveryRequest[]> {
    try {
      const requests = await this.prisma.recoveryRequest.findMany({
        where: {
          userId,
          type,
        },
        orderBy: { initiatedAt: 'desc' },
      });
      return this.mapToModels(requests);
    } catch (error) {
      logger.error('Error finding recovery requests by user ID and type', { userId, type, error });
      throw new DatabaseError(
        'Error finding recovery requests by user ID and type',
        'RECOVERY_REQUEST_FIND_BY_USER_ID_AND_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find recovery requests by status
   * @param status The recovery request status
   * @returns Array of recovery requests
   */
  async findByStatus(status: RecoveryRequestStatus): Promise<RecoveryRequest[]> {
    try {
      const requests = await this.prisma.recoveryRequest.findMany({
        where: { status },
        orderBy: { initiatedAt: 'desc' },
      });
      return this.mapToModels(requests);
    } catch (error) {
      logger.error('Error finding recovery requests by status', { status, error });
      throw new DatabaseError(
        'Error finding recovery requests by status',
        'RECOVERY_REQUEST_FIND_BY_STATUS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find a recovery request with its admin approvals
   * @param id The recovery request ID
   * @returns The recovery request with approvals or null if not found
   */
  async findWithApprovals(id: string): Promise<RecoveryRequestWithApprovals | null> {
    try {
      const request = await this.prisma.recoveryRequest.findUnique({
        where: { id },
        include: {
          adminApprovals: {
            orderBy: { createdAt: 'desc' },
          },
        },
      });

      if (!request) {
        return null;
      }

      return {
        ...this.mapToModel(request),
        adminApprovals: this.mapAdminApprovals(request.adminApprovals),
      };
    } catch (error) {
      logger.error('Error finding recovery request with approvals', { id, error });
      throw new DatabaseError(
        'Error finding recovery request with approvals',
        'RECOVERY_REQUEST_FIND_WITH_APPROVALS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update a recovery request's status
   * @param id The recovery request ID
   * @param status The new status
   * @param completedAt The completion date (if applicable)
   * @returns The updated recovery request
   */
  async updateStatus(
    id: string,
    status: RecoveryRequestStatus,
    completedAt?: Date | null
  ): Promise<RecoveryRequest> {
    try {
      const data: any = { status };

      if (
        status === RecoveryRequestStatus.COMPLETED ||
        status === RecoveryRequestStatus.APPROVED ||
        status === RecoveryRequestStatus.DENIED
      ) {
        data.completedAt = completedAt || new Date();
      }

      const request = await this.prisma.recoveryRequest.update({
        where: { id },
        data,
      });
      return this.mapToModel(request);
    } catch (error) {
      logger.error('Error updating recovery request status', { id, status, error });
      throw new DatabaseError(
        'Error updating recovery request status',
        'RECOVERY_REQUEST_UPDATE_STATUS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Complete a recovery request
   * @param id The recovery request ID
   * @returns The updated recovery request
   */
  async complete(id: string): Promise<RecoveryRequest> {
    return this.updateStatus(id, RecoveryRequestStatus.COMPLETED, new Date());
  }

  /**
   * Cancel a recovery request
   * @param id The recovery request ID
   * @returns The updated recovery request
   */
  async cancel(id: string): Promise<RecoveryRequest> {
    return this.updateStatus(id, RecoveryRequestStatus.CANCELLED);
  }

  /**
   * Expire outdated pending recovery requests
   * @param olderThan Expire requests older than this date
   * @returns Number of expired recovery requests
   */
  async expireOutdated(olderThan: Date): Promise<number> {
    try {
      const result = await this.prisma.recoveryRequest.updateMany({
        where: {
          status: RecoveryRequestStatus.PENDING,
          initiatedAt: {
            lt: olderThan,
          },
        },
        data: {
          status: RecoveryRequestStatus.EXPIRED,
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error expiring outdated recovery requests', { olderThan, error });
      throw new DatabaseError(
        'Error expiring outdated recovery requests',
        'RECOVERY_REQUEST_EXPIRE_OUTDATED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count recovery requests by user ID
   * @param userId The user ID
   * @returns Number of recovery requests
   */
  async countByUserId(userId: string): Promise<number> {
    try {
      const count = await this.prisma.recoveryRequest.count({
        where: { userId },
      });
      return count;
    } catch (error) {
      logger.error('Error counting recovery requests by user ID', { userId, error });
      throw new DatabaseError(
        'Error counting recovery requests by user ID',
        'RECOVERY_REQUEST_COUNT_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count recovery requests by status
   * @param status The recovery request status
   * @returns Number of recovery requests
   */
  async countByStatus(status: RecoveryRequestStatus): Promise<number> {
    try {
      const count = await this.prisma.recoveryRequest.count({
        where: { status },
      });
      return count;
    } catch (error) {
      logger.error('Error counting recovery requests by status', { status, error });
      throw new DatabaseError(
        'Error counting recovery requests by status',
        'RECOVERY_REQUEST_COUNT_BY_STATUS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  protected override toWhereClause(filter?: RecoveryRequestFilterOptions): any {
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

    if (filter.type) {
      where.type = filter.type;
    }

    if (filter.status) {
      where.status = filter.status;
    }

    if (filter.ipAddress) {
      where.ipAddress = filter.ipAddress;
    }

    // Date range filters
    if (filter.initiatedAtBefore || filter.initiatedAtAfter) {
      where.initiatedAt = {};

      if (filter.initiatedAtBefore) {
        where.initiatedAt.lte = filter.initiatedAtBefore;
      }

      if (filter.initiatedAtAfter) {
        where.initiatedAt.gte = filter.initiatedAtAfter;
      }
    }

    if (filter.completedAtBefore || filter.completedAtAfter) {
      where.completedAt = {};

      if (filter.completedAtBefore) {
        where.completedAt.lte = filter.completedAtBefore;
      }

      if (filter.completedAtAfter) {
        where.completedAt.gte = filter.completedAtAfter;
      }
    }

    return where;
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected override withTransaction(tx: PrismaClient): BaseRepository<RecoveryRequest, string> {
    return new PrismaRecoveryRequestRepository(tx);
  }
}

// Export a singleton instance
export const recoveryRequestRepository = new PrismaRecoveryRequestRepository();
