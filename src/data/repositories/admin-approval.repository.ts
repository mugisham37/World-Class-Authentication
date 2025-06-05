import { PrismaClient, AdminApproval as PrismaAdminApproval } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  AdminApproval,
  AdminApprovalStatus,
} from '../models/recovery-request.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * Maps a Prisma AdminApproval to the domain AdminApproval model
 * @param prismaModel The Prisma AdminApproval model
 * @returns The domain AdminApproval model
 */
function mapToDomainModel(prismaModel: PrismaAdminApproval): AdminApproval {
  return {
    ...prismaModel,
    status: prismaModel.status as unknown as AdminApprovalStatus
  };
}

/**
 * Admin approval filter options interface
 * Represents the options for filtering admin approvals
 */
export interface AdminApprovalFilterOptions {
  id?: string;
  recoveryRequestId?: string;
  adminId?: string;
  status?: AdminApprovalStatus;
  createdAtBefore?: Date;
  createdAtAfter?: Date;
  updatedAtBefore?: Date;
  updatedAtAfter?: Date;
}

/**
 * Admin approval repository interface
 * Defines admin approval-specific operations
 */
export interface AdminApprovalRepository extends BaseRepository<AdminApproval, string> {
  /**
   * Find admin approvals by recovery request ID
   * @param recoveryRequestId The recovery request ID
   * @returns Array of admin approvals
   */
  findByRecoveryRequestId(recoveryRequestId: string): Promise<AdminApproval[]>;

  /**
   * Find admin approvals by admin ID
   * @param adminId The admin ID
   * @returns Array of admin approvals
   */
  findByAdminId(adminId: string): Promise<AdminApproval[]>;

  /**
   * Find admin approvals by recovery request ID and status
   * @param recoveryRequestId The recovery request ID
   * @param status The admin approval status
   * @returns Array of admin approvals
   */
  findByRecoveryRequestIdAndStatus(
    recoveryRequestId: string,
    status: AdminApprovalStatus
  ): Promise<AdminApproval[]>;

  /**
   * Find admin approval by recovery request ID and admin ID
   * @param recoveryRequestId The recovery request ID
   * @param adminId The admin ID
   * @returns The admin approval or null if not found
   */
  findByRecoveryRequestIdAndAdminId(
    recoveryRequestId: string,
    adminId: string
  ): Promise<AdminApproval | null>;

  /**
   * Update an admin approval's status
   * @param id The admin approval ID
   * @param status The new status
   * @param notes Optional notes to add
   * @returns The updated admin approval
   */
  updateStatus(id: string, status: AdminApprovalStatus, notes?: string): Promise<AdminApproval>;

  /**
   * Approve an admin approval
   * @param id The admin approval ID
   * @param notes Optional notes to add
   * @returns The updated admin approval
   */
  approve(id: string, notes?: string): Promise<AdminApproval>;

  /**
   * Deny an admin approval
   * @param id The admin approval ID
   * @param notes Optional notes to add
   * @returns The updated admin approval
   */
  deny(id: string, notes?: string): Promise<AdminApproval>;

  /**
   * Count admin approvals by recovery request ID
   * @param recoveryRequestId The recovery request ID
   * @returns Number of admin approvals
   */
  countByRecoveryRequestId(recoveryRequestId: string): Promise<number>;

  /**
   * Count admin approvals by recovery request ID and status
   * @param recoveryRequestId The recovery request ID
   * @param status The admin approval status
   * @returns Number of admin approvals
   */
  countByRecoveryRequestIdAndStatus(
    recoveryRequestId: string,
    status: AdminApprovalStatus
  ): Promise<number>;

  /**
   * Check if an admin has already approved or denied a recovery request
   * @param recoveryRequestId The recovery request ID
   * @param adminId The admin ID
   * @returns True if the admin has already approved or denied the recovery request, false otherwise
   */
  hasAdminResponded(recoveryRequestId: string, adminId: string): Promise<boolean>;
}

/**
 * Prisma implementation of the admin approval repository
 */
export class PrismaAdminApprovalRepository
  extends PrismaBaseRepository<AdminApproval, string>
  implements AdminApprovalRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'adminApproval';

  /**
   * Find admin approvals by recovery request ID
   * @param recoveryRequestId The recovery request ID
   * @returns Array of admin approvals
   */
  async findByRecoveryRequestId(recoveryRequestId: string): Promise<AdminApproval[]> {
    try {
      const approvals = await this.prisma.adminApproval.findMany({
        where: { recoveryRequestId },
        orderBy: { createdAt: 'desc' },
      });
      return approvals.map(mapToDomainModel);
    } catch (error) {
      logger.error('Error finding admin approvals by recovery request ID', {
        recoveryRequestId,
        error,
      });
      throw new DatabaseError(
        'Error finding admin approvals by recovery request ID',
        'ADMIN_APPROVAL_FIND_BY_RECOVERY_REQUEST_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find admin approvals by admin ID
   * @param adminId The admin ID
   * @returns Array of admin approvals
   */
  async findByAdminId(adminId: string): Promise<AdminApproval[]> {
    try {
      const approvals = await this.prisma.adminApproval.findMany({
        where: { adminId },
        orderBy: { createdAt: 'desc' },
      });
      return approvals.map(mapToDomainModel);
    } catch (error) {
      logger.error('Error finding admin approvals by admin ID', { adminId, error });
      throw new DatabaseError(
        'Error finding admin approvals by admin ID',
        'ADMIN_APPROVAL_FIND_BY_ADMIN_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find admin approvals by recovery request ID and status
   * @param recoveryRequestId The recovery request ID
   * @param status The admin approval status
   * @returns Array of admin approvals
   */
  async findByRecoveryRequestIdAndStatus(
    recoveryRequestId: string,
    status: AdminApprovalStatus
  ): Promise<AdminApproval[]> {
    try {
      const approvals = await this.prisma.adminApproval.findMany({
        where: {
          recoveryRequestId,
          status: status as unknown as any,
        },
        orderBy: { createdAt: 'desc' },
      });
      return approvals.map(mapToDomainModel);
    } catch (error) {
      logger.error('Error finding admin approvals by recovery request ID and status', {
        recoveryRequestId,
        status,
        error,
      });
      throw new DatabaseError(
        'Error finding admin approvals by recovery request ID and status',
        'ADMIN_APPROVAL_FIND_BY_RECOVERY_REQUEST_ID_AND_STATUS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find admin approval by recovery request ID and admin ID
   * @param recoveryRequestId The recovery request ID
   * @param adminId The admin ID
   * @returns The admin approval or null if not found
   */
  async findByRecoveryRequestIdAndAdminId(
    recoveryRequestId: string,
    adminId: string
  ): Promise<AdminApproval | null> {
    try {
      const approval = await this.prisma.adminApproval.findFirst({
        where: {
          recoveryRequestId,
          adminId,
        },
      });
      return approval ? mapToDomainModel(approval) : null;
    } catch (error) {
      logger.error('Error finding admin approval by recovery request ID and admin ID', {
        recoveryRequestId,
        adminId,
        error,
      });
      throw new DatabaseError(
        'Error finding admin approval by recovery request ID and admin ID',
        'ADMIN_APPROVAL_FIND_BY_RECOVERY_REQUEST_ID_AND_ADMIN_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update an admin approval's status
   * @param id The admin approval ID
   * @param status The new status
   * @param notes Optional notes to add
   * @returns The updated admin approval
   */
  async updateStatus(
    id: string,
    status: AdminApprovalStatus,
    notes?: string
  ): Promise<AdminApproval> {
    try {
      const data: any = { status: status as unknown as any };

      if (notes !== undefined) {
        data.notes = notes;
      }

      const approval = await this.prisma.adminApproval.update({
        where: { id },
        data,
      });
      return mapToDomainModel(approval);
    } catch (error) {
      logger.error('Error updating admin approval status', { id, status, notes, error });
      throw new DatabaseError(
        'Error updating admin approval status',
        'ADMIN_APPROVAL_UPDATE_STATUS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Approve an admin approval
   * @param id The admin approval ID
   * @param notes Optional notes to add
   * @returns The updated admin approval
   */
  async approve(id: string, notes?: string): Promise<AdminApproval> {
    return this.updateStatus(id, AdminApprovalStatus.APPROVED, notes);
  }

  /**
   * Deny an admin approval
   * @param id The admin approval ID
   * @param notes Optional notes to add
   * @returns The updated admin approval
   */
  async deny(id: string, notes?: string): Promise<AdminApproval> {
    return this.updateStatus(id, AdminApprovalStatus.DENIED, notes);
  }

  /**
   * Count admin approvals by recovery request ID
   * @param recoveryRequestId The recovery request ID
   * @returns Number of admin approvals
   */
  async countByRecoveryRequestId(recoveryRequestId: string): Promise<number> {
    try {
      const count = await this.prisma.adminApproval.count({
        where: { recoveryRequestId },
      });
      return count;
    } catch (error) {
      logger.error('Error counting admin approvals by recovery request ID', {
        recoveryRequestId,
        error,
      });
      throw new DatabaseError(
        'Error counting admin approvals by recovery request ID',
        'ADMIN_APPROVAL_COUNT_BY_RECOVERY_REQUEST_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count admin approvals by recovery request ID and status
   * @param recoveryRequestId The recovery request ID
   * @param status The admin approval status
   * @returns Number of admin approvals
   */
  async countByRecoveryRequestIdAndStatus(
    recoveryRequestId: string,
    status: AdminApprovalStatus
  ): Promise<number> {
    try {
      const count = await this.prisma.adminApproval.count({
        where: {
          recoveryRequestId,
          status: status as unknown as any,
        },
      });
      return count;
    } catch (error) {
      logger.error('Error counting admin approvals by recovery request ID and status', {
        recoveryRequestId,
        status,
        error,
      });
      throw new DatabaseError(
        'Error counting admin approvals by recovery request ID and status',
        'ADMIN_APPROVAL_COUNT_BY_RECOVERY_REQUEST_ID_AND_STATUS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check if an admin has already approved or denied a recovery request
   * @param recoveryRequestId The recovery request ID
   * @param adminId The admin ID
   * @returns True if the admin has already approved or denied the recovery request, false otherwise
   */
  async hasAdminResponded(recoveryRequestId: string, adminId: string): Promise<boolean> {
    try {
      const count = await this.prisma.adminApproval.count({
        where: {
          recoveryRequestId,
          adminId,
          status: {
            in: [
              AdminApprovalStatus.APPROVED as unknown as any, 
              AdminApprovalStatus.DENIED as unknown as any
            ],
          },
        },
      });
      return count > 0;
    } catch (error) {
      logger.error('Error checking if admin has responded to recovery request', {
        recoveryRequestId,
        adminId,
        error,
      });
      throw new DatabaseError(
        'Error checking if admin has responded to recovery request',
        'ADMIN_APPROVAL_HAS_ADMIN_RESPONDED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  protected override toWhereClause(filter?: AdminApprovalFilterOptions): any {
    if (!filter) {
      return {};
    }

    const where: any = {};

    if (filter.id) {
      where.id = filter.id;
    }

    if (filter.recoveryRequestId) {
      where.recoveryRequestId = filter.recoveryRequestId;
    }

    if (filter.adminId) {
      where.adminId = filter.adminId;
    }

    if (filter.status) {
      where.status = filter.status as unknown as any;
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

    if (filter.updatedAtBefore || filter.updatedAtAfter) {
      where.updatedAt = {};

      if (filter.updatedAtBefore) {
        where.updatedAt.lte = filter.updatedAtBefore;
      }

      if (filter.updatedAtAfter) {
        where.updatedAt.gte = filter.updatedAtAfter;
      }
    }

    return where;
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected override withTransaction(tx: PrismaClient): BaseRepository<AdminApproval, string> {
    return new PrismaAdminApprovalRepository(tx);
  }
}

// Export a singleton instance
export const adminApprovalRepository = new PrismaAdminApprovalRepository();
