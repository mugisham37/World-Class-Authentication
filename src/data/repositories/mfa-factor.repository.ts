import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  MfaFactor,
  MfaFactorType,
  MfaFactorStatus,
  CreateMfaFactorData,
  UpdateMfaFactorData,
  MfaFactorFilterOptions,
} from '../models/mfa-factor.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * MFA factor repository interface
 * Defines MFA factor-specific operations
 */
export interface MfaFactorRepository extends BaseRepository<MfaFactor, string> {
  /**
   * Find MFA factors by user ID
   * @param userId The user ID
   * @returns Array of MFA factors
   */
  findByUserId(userId: string): Promise<MfaFactor[]>;

  /**
   * Find active MFA factors by user ID
   * @param userId The user ID
   * @returns Array of active MFA factors
   */
  findActiveByUserId(userId: string): Promise<MfaFactor[]>;

  /**
   * Find MFA factors by user ID and type
   * @param userId The user ID
   * @param type The MFA factor type
   * @returns Array of MFA factors
   */
  findByUserIdAndType(userId: string, type: MfaFactorType): Promise<MfaFactor[]>;

  /**
   * Find a verified MFA factor by user ID and type
   * @param userId The user ID
   * @param type The MFA factor type
   * @returns The MFA factor or null if not found
   */
  findVerifiedByUserIdAndType(userId: string, type: MfaFactorType): Promise<MfaFactor | null>;

  /**
   * Update an MFA factor's last used time
   * @param id The MFA factor ID
   * @returns The updated MFA factor
   */
  updateLastUsed(id: string): Promise<MfaFactor>;

  /**
   * Verify an MFA factor
   * @param id The MFA factor ID
   * @returns The updated MFA factor
   */
  verify(id: string): Promise<MfaFactor>;

  /**
   * Change an MFA factor's status
   * @param id The MFA factor ID
   * @param status The new status
   * @returns The updated MFA factor
   */
  changeStatus(id: string, status: MfaFactorStatus): Promise<MfaFactor>;

  /**
   * Delete MFA factors by user ID
   * @param userId The user ID
   * @returns Number of deleted MFA factors
   */
  deleteByUserId(userId: string): Promise<number>;

  /**
   * Delete MFA factors by user ID and type
   * @param userId The user ID
   * @param type The MFA factor type
   * @returns Number of deleted MFA factors
   */
  deleteByUserIdAndType(userId: string, type: MfaFactorType): Promise<number>;

  /**
   * Count MFA factors by user ID
   * @param userId The user ID
   * @returns Number of MFA factors
   */
  countByUserId(userId: string): Promise<number>;

  /**
   * Count active MFA factors by user ID
   * @param userId The user ID
   * @returns Number of active MFA factors
   */
  countActiveByUserId(userId: string): Promise<number>;

  /**
   * Check if a user has a verified MFA factor of a specific type
   * @param userId The user ID
   * @param type The MFA factor type
   * @returns True if the user has a verified MFA factor of the specified type, false otherwise
   */
  hasVerifiedFactorOfType(userId: string, type: MfaFactorType): Promise<boolean>;
}

/**
 * Prisma implementation of the MFA factor repository
 */
export class PrismaMfaFactorRepository
  extends PrismaBaseRepository<MfaFactor, string>
  implements MfaFactorRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'mfaFactor';

  /**
   * Find MFA factors by user ID
   * @param userId The user ID
   * @returns Array of MFA factors
   */
  async findByUserId(userId: string): Promise<MfaFactor[]> {
    try {
      const factors = await this.prisma.mfaFactor.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
      });
      return factors;
    } catch (error) {
      logger.error('Error finding MFA factors by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding MFA factors by user ID',
        'MFA_FACTOR_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find active MFA factors by user ID
   * @param userId The user ID
   * @returns Array of active MFA factors
   */
  async findActiveByUserId(userId: string): Promise<MfaFactor[]> {
    try {
      const factors = await this.prisma.mfaFactor.findMany({
        where: {
          userId,
          status: MfaFactorStatus.ACTIVE,
        },
        orderBy: { createdAt: 'desc' },
      });
      return factors;
    } catch (error) {
      logger.error('Error finding active MFA factors by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding active MFA factors by user ID',
        'MFA_FACTOR_FIND_ACTIVE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find MFA factors by user ID and type
   * @param userId The user ID
   * @param type The MFA factor type
   * @returns Array of MFA factors
   */
  async findByUserIdAndType(userId: string, type: MfaFactorType): Promise<MfaFactor[]> {
    try {
      const factors = await this.prisma.mfaFactor.findMany({
        where: {
          userId,
          type,
        },
        orderBy: { createdAt: 'desc' },
      });
      return factors;
    } catch (error) {
      logger.error('Error finding MFA factors by user ID and type', { userId, type, error });
      throw new DatabaseError(
        'Error finding MFA factors by user ID and type',
        'MFA_FACTOR_FIND_BY_USER_ID_AND_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find a verified MFA factor by user ID and type
   * @param userId The user ID
   * @param type The MFA factor type
   * @returns The MFA factor or null if not found
   */
  async findVerifiedByUserIdAndType(
    userId: string,
    type: MfaFactorType
  ): Promise<MfaFactor | null> {
    try {
      const factor = await this.prisma.mfaFactor.findFirst({
        where: {
          userId,
          type,
          status: MfaFactorStatus.ACTIVE,
          verifiedAt: {
            not: null,
          },
        },
        orderBy: { lastUsedAt: 'desc' },
      });
      return factor;
    } catch (error) {
      logger.error('Error finding verified MFA factor by user ID and type', {
        userId,
        type,
        error,
      });
      throw new DatabaseError(
        'Error finding verified MFA factor by user ID and type',
        'MFA_FACTOR_FIND_VERIFIED_BY_USER_ID_AND_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update an MFA factor's last used time
   * @param id The MFA factor ID
   * @returns The updated MFA factor
   */
  async updateLastUsed(id: string): Promise<MfaFactor> {
    try {
      const factor = await this.prisma.mfaFactor.update({
        where: { id },
        data: {
          lastUsedAt: new Date(),
        },
      });
      return factor;
    } catch (error) {
      logger.error('Error updating MFA factor last used time', { id, error });
      throw new DatabaseError(
        'Error updating MFA factor last used time',
        'MFA_FACTOR_UPDATE_LAST_USED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Verify an MFA factor
   * @param id The MFA factor ID
   * @returns The updated MFA factor
   */
  async verify(id: string): Promise<MfaFactor> {
    try {
      const factor = await this.prisma.mfaFactor.update({
        where: { id },
        data: {
          verifiedAt: new Date(),
          status: MfaFactorStatus.ACTIVE,
        },
      });
      return factor;
    } catch (error) {
      logger.error('Error verifying MFA factor', { id, error });
      throw new DatabaseError(
        'Error verifying MFA factor',
        'MFA_FACTOR_VERIFY_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Change an MFA factor's status
   * @param id The MFA factor ID
   * @param status The new status
   * @returns The updated MFA factor
   */
  async changeStatus(id: string, status: MfaFactorStatus): Promise<MfaFactor> {
    try {
      const factor = await this.prisma.mfaFactor.update({
        where: { id },
        data: { status },
      });
      return factor;
    } catch (error) {
      logger.error('Error changing MFA factor status', { id, status, error });
      throw new DatabaseError(
        'Error changing MFA factor status',
        'MFA_FACTOR_CHANGE_STATUS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete MFA factors by user ID
   * @param userId The user ID
   * @returns Number of deleted MFA factors
   */
  async deleteByUserId(userId: string): Promise<number> {
    try {
      const result = await this.prisma.mfaFactor.deleteMany({
        where: { userId },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting MFA factors by user ID', { userId, error });
      throw new DatabaseError(
        'Error deleting MFA factors by user ID',
        'MFA_FACTOR_DELETE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete MFA factors by user ID and type
   * @param userId The user ID
   * @param type The MFA factor type
   * @returns Number of deleted MFA factors
   */
  async deleteByUserIdAndType(userId: string, type: MfaFactorType): Promise<number> {
    try {
      const result = await this.prisma.mfaFactor.deleteMany({
        where: {
          userId,
          type,
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting MFA factors by user ID and type', { userId, type, error });
      throw new DatabaseError(
        'Error deleting MFA factors by user ID and type',
        'MFA_FACTOR_DELETE_BY_USER_ID_AND_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count MFA factors by user ID
   * @param userId The user ID
   * @returns Number of MFA factors
   */
  async countByUserId(userId: string): Promise<number> {
    try {
      const count = await this.prisma.mfaFactor.count({
        where: { userId },
      });
      return count;
    } catch (error) {
      logger.error('Error counting MFA factors by user ID', { userId, error });
      throw new DatabaseError(
        'Error counting MFA factors by user ID',
        'MFA_FACTOR_COUNT_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count active MFA factors by user ID
   * @param userId The user ID
   * @returns Number of active MFA factors
   */
  async countActiveByUserId(userId: string): Promise<number> {
    try {
      const count = await this.prisma.mfaFactor.count({
        where: {
          userId,
          status: MfaFactorStatus.ACTIVE,
        },
      });
      return count;
    } catch (error) {
      logger.error('Error counting active MFA factors by user ID', { userId, error });
      throw new DatabaseError(
        'Error counting active MFA factors by user ID',
        'MFA_FACTOR_COUNT_ACTIVE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check if a user has a verified MFA factor of a specific type
   * @param userId The user ID
   * @param type The MFA factor type
   * @returns True if the user has a verified MFA factor of the specified type, false otherwise
   */
  async hasVerifiedFactorOfType(userId: string, type: MfaFactorType): Promise<boolean> {
    try {
      const count = await this.prisma.mfaFactor.count({
        where: {
          userId,
          type,
          status: MfaFactorStatus.ACTIVE,
          verifiedAt: {
            not: null,
          },
        },
      });
      return count > 0;
    } catch (error) {
      logger.error('Error checking if user has verified MFA factor of type', {
        userId,
        type,
        error,
      });
      throw new DatabaseError(
        'Error checking if user has verified MFA factor of type',
        'MFA_FACTOR_HAS_VERIFIED_OF_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  protected override toWhereClause(filter?: MfaFactorFilterOptions): any {
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

    if (filter.verifiedOnly) {
      where.verifiedAt = {
        not: null,
      };
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

    if (filter.verifiedAtBefore || filter.verifiedAtAfter) {
      where.verifiedAt = where.verifiedAt || {};

      if (filter.verifiedAtBefore) {
        where.verifiedAt.lte = filter.verifiedAtBefore;
      }

      if (filter.verifiedAtAfter) {
        where.verifiedAt.gte = filter.verifiedAtAfter;
      }
    }

    return where;
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected override withTransaction(tx: PrismaClient): BaseRepository<MfaFactor, string> {
    return new PrismaMfaFactorRepository(tx);
  }
}

// Export a singleton instance
export const mfaFactorRepository = new PrismaMfaFactorRepository();
