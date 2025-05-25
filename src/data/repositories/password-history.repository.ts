import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  PasswordHistory,
  CreatePasswordHistoryData,
  PasswordHistoryFilterOptions,
} from '../models/password-history.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';
import { prisma } from '../prisma/client';

/**
 * Password history repository interface
 * Defines password history-specific operations
 */
export interface PasswordHistoryRepository extends BaseRepository<PasswordHistory, string> {
  /**
   * Find password history entries by user ID
   * @param userId User ID
   * @param limit Maximum number of entries to return
   * @returns List of password history entries
   */
  findByUserId(userId: string, limit?: number): Promise<PasswordHistory[]>;

  /**
   * Find password history entries by credential ID
   * @param credentialId Credential ID
   * @param limit Maximum number of entries to return
   * @returns List of password history entries
   */
  findByCredentialId(credentialId: string, limit?: number): Promise<PasswordHistory[]>;

  /**
   * Check if a password hash exists in the user's history
   * @param userId User ID
   * @param passwordHash Password hash to check
   * @returns True if the password hash exists in the user's history, false otherwise
   */
  existsByUserIdAndPasswordHash(userId: string, passwordHash: string): Promise<boolean>;

  /**
   * Delete password history entries by user ID
   * @param userId User ID
   * @returns Number of deleted entries
   */
  deleteByUserId(userId: string): Promise<number>;

  /**
   * Delete password history entries by credential ID
   * @param credentialId Credential ID
   * @returns Number of deleted entries
   */
  deleteByCredentialId(credentialId: string): Promise<number>;

  /**
   * Delete old password history entries for a user
   * @param userId User ID
   * @param maxEntries Maximum number of entries to keep
   * @returns Number of deleted entries
   */
  deleteOldEntries(userId: string, maxEntries: number): Promise<number>;
}

/**
 * Prisma implementation of the password history repository
 */
export class PrismaPasswordHistoryRepository
  extends PrismaBaseRepository<PasswordHistory, string>
  implements PasswordHistoryRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'passwordHistory';

  /**
   * Find password history entries by user ID
   * @param userId User ID
   * @param limit Maximum number of entries to return
   * @returns List of password history entries
   */
  async findByUserId(userId: string, limit?: number): Promise<PasswordHistory[]> {
    try {
      const entries = await this.prisma.passwordHistory.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        take: limit,
      });
      return entries;
    } catch (error) {
      logger.error('Error finding password history entries by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding password history entries by user ID',
        'PASSWORD_HISTORY_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find password history entries by credential ID
   * @param credentialId Credential ID
   * @param limit Maximum number of entries to return
   * @returns List of password history entries
   */
  async findByCredentialId(credentialId: string, limit?: number): Promise<PasswordHistory[]> {
    try {
      const entries = await this.prisma.passwordHistory.findMany({
        where: { credentialId },
        orderBy: { createdAt: 'desc' },
        take: limit,
      });
      return entries;
    } catch (error) {
      logger.error('Error finding password history entries by credential ID', {
        credentialId,
        error,
      });
      throw new DatabaseError(
        'Error finding password history entries by credential ID',
        'PASSWORD_HISTORY_FIND_BY_CREDENTIAL_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check if a password hash exists in the user's history
   * @param userId User ID
   * @param passwordHash Password hash to check
   * @returns True if the password hash exists in the user's history, false otherwise
   */
  async existsByUserIdAndPasswordHash(userId: string, passwordHash: string): Promise<boolean> {
    try {
      const count = await this.prisma.passwordHistory.count({
        where: {
          userId,
          passwordHash,
        },
      });
      return count > 0;
    } catch (error) {
      logger.error('Error checking if password hash exists in user history', {
        userId,
        error,
      });
      throw new DatabaseError(
        'Error checking if password hash exists in user history',
        'PASSWORD_HISTORY_EXISTS_BY_USER_ID_AND_PASSWORD_HASH_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete password history entries by user ID
   * @param userId User ID
   * @returns Number of deleted entries
   */
  async deleteByUserId(userId: string): Promise<number> {
    try {
      const result = await this.prisma.passwordHistory.deleteMany({
        where: { userId },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting password history entries by user ID', { userId, error });
      throw new DatabaseError(
        'Error deleting password history entries by user ID',
        'PASSWORD_HISTORY_DELETE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete password history entries by credential ID
   * @param credentialId Credential ID
   * @returns Number of deleted entries
   */
  async deleteByCredentialId(credentialId: string): Promise<number> {
    try {
      const result = await this.prisma.passwordHistory.deleteMany({
        where: { credentialId },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting password history entries by credential ID', {
        credentialId,
        error,
      });
      throw new DatabaseError(
        'Error deleting password history entries by credential ID',
        'PASSWORD_HISTORY_DELETE_BY_CREDENTIAL_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete old password history entries for a user
   * @param userId User ID
   * @param maxEntries Maximum number of entries to keep
   * @returns Number of deleted entries
   */
  async deleteOldEntries(userId: string, maxEntries: number): Promise<number> {
    try {
      // Get the IDs of the entries to keep (the most recent ones)
      const recentEntries = await this.prisma.passwordHistory.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        take: maxEntries,
        select: { id: true },
      });

      const recentEntryIds = recentEntries.map((entry: { id: string }) => entry.id);

      // Delete all entries for the user except the recent ones
      const result = await this.prisma.passwordHistory.deleteMany({
        where: {
          userId,
          id: {
            notIn: recentEntryIds,
          },
        },
      });

      return result.count;
    } catch (error) {
      logger.error('Error deleting old password history entries', { userId, maxEntries, error });
      throw new DatabaseError(
        'Error deleting old password history entries',
        'PASSWORD_HISTORY_DELETE_OLD_ENTRIES_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  private buildWhereClause(filter?: PasswordHistoryFilterOptions): any {
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

    if (filter.credentialId) {
      where.credentialId = filter.credentialId;
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
  protected withTransaction(tx: PrismaClient): BaseRepository<PasswordHistory, string> {
    return new PrismaPasswordHistoryRepository(tx);
  }
}

// Export a singleton instance
export const passwordHistoryRepository = new PrismaPasswordHistoryRepository();
