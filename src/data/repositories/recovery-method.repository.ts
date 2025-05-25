import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  RecoveryMethod,
  RecoveryMethodType,
  RecoveryMethodStatus,
  CreateRecoveryMethodData,
  UpdateRecoveryMethodData,
  RecoveryMethodFilterOptions,
} from '../models/recovery-method.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * Recovery method repository interface
 * Defines recovery method-specific operations
 */
export interface RecoveryMethodRepository extends BaseRepository<RecoveryMethod, string> {
  /**
   * Find recovery methods by user ID
   * @param userId The user ID
   * @returns Array of recovery methods
   */
  findByUserId(userId: string): Promise<RecoveryMethod[]>;

  /**
   * Find active recovery methods by user ID
   * @param userId The user ID
   * @returns Array of active recovery methods
   */
  findActiveByUserId(userId: string): Promise<RecoveryMethod[]>;

  /**
   * Find recovery methods by user ID and type
   * @param userId The user ID
   * @param type The recovery method type
   * @returns Array of recovery methods
   */
  findByUserIdAndType(userId: string, type: RecoveryMethodType): Promise<RecoveryMethod[]>;

  /**
   * Find active recovery methods by user ID and type
   * @param userId The user ID
   * @param type The recovery method type
   * @returns Array of active recovery methods
   */
  findActiveByUserIdAndType(userId: string, type: RecoveryMethodType): Promise<RecoveryMethod[]>;

  /**
   * Update a recovery method's last used time
   * @param id The recovery method ID
   * @returns The updated recovery method
   */
  updateLastUsed(id: string): Promise<RecoveryMethod>;

  /**
   * Change a recovery method's status
   * @param id The recovery method ID
   * @param status The new status
   * @returns The updated recovery method
   */
  changeStatus(id: string, status: RecoveryMethodStatus): Promise<RecoveryMethod>;

  /**
   * Delete recovery methods by user ID
   * @param userId The user ID
   * @returns Number of deleted recovery methods
   */
  deleteByUserId(userId: string): Promise<number>;

  /**
   * Delete recovery methods by user ID and type
   * @param userId The user ID
   * @param type The recovery method type
   * @returns Number of deleted recovery methods
   */
  deleteByUserIdAndType(userId: string, type: RecoveryMethodType): Promise<number>;

  /**
   * Count recovery methods by user ID
   * @param userId The user ID
   * @returns Number of recovery methods
   */
  countByUserId(userId: string): Promise<number>;

  /**
   * Count active recovery methods by user ID
   * @param userId The user ID
   * @returns Number of active recovery methods
   */
  countActiveByUserId(userId: string): Promise<number>;

  /**
   * Check if a user has an active recovery method of a specific type
   * @param userId The user ID
   * @param type The recovery method type
   * @returns True if the user has an active recovery method of the specified type, false otherwise
   */
  hasActiveMethodOfType(userId: string, type: RecoveryMethodType): Promise<boolean>;
}

/**
 * Prisma implementation of the recovery method repository
 */
export class PrismaRecoveryMethodRepository
  extends PrismaBaseRepository<RecoveryMethod, string>
  implements RecoveryMethodRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'recoveryMethod';

  /**
   * Find recovery methods by user ID
   * @param userId The user ID
   * @returns Array of recovery methods
   */
  async findByUserId(userId: string): Promise<RecoveryMethod[]> {
    try {
      const methods = await this.prisma.recoveryMethod.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
      });
      return methods;
    } catch (error) {
      logger.error('Error finding recovery methods by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding recovery methods by user ID',
        'RECOVERY_METHOD_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find active recovery methods by user ID
   * @param userId The user ID
   * @returns Array of active recovery methods
   */
  async findActiveByUserId(userId: string): Promise<RecoveryMethod[]> {
    try {
      const methods = await this.prisma.recoveryMethod.findMany({
        where: {
          userId,
          status: RecoveryMethodStatus.ACTIVE,
        },
        orderBy: { createdAt: 'desc' },
      });
      return methods;
    } catch (error) {
      logger.error('Error finding active recovery methods by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding active recovery methods by user ID',
        'RECOVERY_METHOD_FIND_ACTIVE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find recovery methods by user ID and type
   * @param userId The user ID
   * @param type The recovery method type
   * @returns Array of recovery methods
   */
  async findByUserIdAndType(userId: string, type: RecoveryMethodType): Promise<RecoveryMethod[]> {
    try {
      const methods = await this.prisma.recoveryMethod.findMany({
        where: {
          userId,
          type,
        },
        orderBy: { createdAt: 'desc' },
      });
      return methods;
    } catch (error) {
      logger.error('Error finding recovery methods by user ID and type', { userId, type, error });
      throw new DatabaseError(
        'Error finding recovery methods by user ID and type',
        'RECOVERY_METHOD_FIND_BY_USER_ID_AND_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find active recovery methods by user ID and type
   * @param userId The user ID
   * @param type The recovery method type
   * @returns Array of active recovery methods
   */
  async findActiveByUserIdAndType(
    userId: string,
    type: RecoveryMethodType
  ): Promise<RecoveryMethod[]> {
    try {
      const methods = await this.prisma.recoveryMethod.findMany({
        where: {
          userId,
          type,
          status: RecoveryMethodStatus.ACTIVE,
        },
        orderBy: { createdAt: 'desc' },
      });
      return methods;
    } catch (error) {
      logger.error('Error finding active recovery methods by user ID and type', {
        userId,
        type,
        error,
      });
      throw new DatabaseError(
        'Error finding active recovery methods by user ID and type',
        'RECOVERY_METHOD_FIND_ACTIVE_BY_USER_ID_AND_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update a recovery method's last used time
   * @param id The recovery method ID
   * @returns The updated recovery method
   */
  async updateLastUsed(id: string): Promise<RecoveryMethod> {
    try {
      const method = await this.prisma.recoveryMethod.update({
        where: { id },
        data: {
          lastUsedAt: new Date(),
        },
      });
      return method;
    } catch (error) {
      logger.error('Error updating recovery method last used time', { id, error });
      throw new DatabaseError(
        'Error updating recovery method last used time',
        'RECOVERY_METHOD_UPDATE_LAST_USED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Change a recovery method's status
   * @param id The recovery method ID
   * @param status The new status
   * @returns The updated recovery method
   */
  async changeStatus(id: string, status: RecoveryMethodStatus): Promise<RecoveryMethod> {
    try {
      const method = await this.prisma.recoveryMethod.update({
        where: { id },
        data: { status },
      });
      return method;
    } catch (error) {
      logger.error('Error changing recovery method status', { id, status, error });
      throw new DatabaseError(
        'Error changing recovery method status',
        'RECOVERY_METHOD_CHANGE_STATUS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete recovery methods by user ID
   * @param userId The user ID
   * @returns Number of deleted recovery methods
   */
  async deleteByUserId(userId: string): Promise<number> {
    try {
      const result = await this.prisma.recoveryMethod.deleteMany({
        where: { userId },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting recovery methods by user ID', { userId, error });
      throw new DatabaseError(
        'Error deleting recovery methods by user ID',
        'RECOVERY_METHOD_DELETE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete recovery methods by user ID and type
   * @param userId The user ID
   * @param type The recovery method type
   * @returns Number of deleted recovery methods
   */
  async deleteByUserIdAndType(userId: string, type: RecoveryMethodType): Promise<number> {
    try {
      const result = await this.prisma.recoveryMethod.deleteMany({
        where: {
          userId,
          type,
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting recovery methods by user ID and type', { userId, type, error });
      throw new DatabaseError(
        'Error deleting recovery methods by user ID and type',
        'RECOVERY_METHOD_DELETE_BY_USER_ID_AND_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count recovery methods by user ID
   * @param userId The user ID
   * @returns Number of recovery methods
   */
  async countByUserId(userId: string): Promise<number> {
    try {
      const count = await this.prisma.recoveryMethod.count({
        where: { userId },
      });
      return count;
    } catch (error) {
      logger.error('Error counting recovery methods by user ID', { userId, error });
      throw new DatabaseError(
        'Error counting recovery methods by user ID',
        'RECOVERY_METHOD_COUNT_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count active recovery methods by user ID
   * @param userId The user ID
   * @returns Number of active recovery methods
   */
  async countActiveByUserId(userId: string): Promise<number> {
    try {
      const count = await this.prisma.recoveryMethod.count({
        where: {
          userId,
          status: RecoveryMethodStatus.ACTIVE,
        },
      });
      return count;
    } catch (error) {
      logger.error('Error counting active recovery methods by user ID', { userId, error });
      throw new DatabaseError(
        'Error counting active recovery methods by user ID',
        'RECOVERY_METHOD_COUNT_ACTIVE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check if a user has an active recovery method of a specific type
   * @param userId The user ID
   * @param type The recovery method type
   * @returns True if the user has an active recovery method of the specified type, false otherwise
   */
  async hasActiveMethodOfType(userId: string, type: RecoveryMethodType): Promise<boolean> {
    try {
      const count = await this.prisma.recoveryMethod.count({
        where: {
          userId,
          type,
          status: RecoveryMethodStatus.ACTIVE,
        },
      });
      return count > 0;
    } catch (error) {
      logger.error('Error checking if user has active recovery method of type', {
        userId,
        type,
        error,
      });
      throw new DatabaseError(
        'Error checking if user has active recovery method of type',
        'RECOVERY_METHOD_HAS_ACTIVE_OF_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  protected override toWhereClause(filter?: RecoveryMethodFilterOptions): any {
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

    if (filter.lastUsedAtBefore || filter.lastUsedAtAfter) {
      where.lastUsedAt = {};

      if (filter.lastUsedAtBefore) {
        where.lastUsedAt.lte = filter.lastUsedAtBefore;
      }

      if (filter.lastUsedAtAfter) {
        where.lastUsedAt.gte = filter.lastUsedAtAfter;
      }
    }

    return where;
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected override withTransaction(tx: PrismaClient): BaseRepository<RecoveryMethod, string> {
    return new PrismaRecoveryMethodRepository(tx);
  }
}

// Export a singleton instance
export const recoveryMethodRepository = new PrismaRecoveryMethodRepository();
