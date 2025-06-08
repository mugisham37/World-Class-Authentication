import { Prisma, PasswordHistory as PrismaPasswordHistory } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  PasswordHistory,
  PasswordHistoryFilterOptions,
  CreatePasswordHistoryData,
} from '../models/password-history.model';
import { BaseRepository, QueryOptions } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';
import { TransactionClient } from '../types/prisma-types';

/**
 * Password history repository interface
 * Defines password history-specific operations
 */
export interface PasswordHistoryRepository extends BaseRepository<PasswordHistory, string> {
  /**
   * Find password history entries by user ID
   * @param userId The user ID
   * @param options Optional query options
   * @returns Array of password history entries
   */
  findByUserId(userId: string, options?: QueryOptions): Promise<PasswordHistory[]>;

  /**
   * Find password history entries by credential ID
   * @param credentialId The credential ID
   * @param options Optional query options
   * @returns Array of password history entries
   */
  findByCredentialId(credentialId: string, options?: QueryOptions): Promise<PasswordHistory[]>;

  /**
   * Find password history entries by user ID and credential ID
   * @param userId The user ID
   * @param credentialId The credential ID
   * @param options Optional query options
   * @returns Array of password history entries
   */
  findByUserIdAndCredentialId(
    userId: string,
    credentialId: string,
    options?: QueryOptions
  ): Promise<PasswordHistory[]>;

  /**
   * Find recent password history entries by user ID
   * @param userId The user ID
   * @param limit The maximum number of entries to return
   * @returns Array of password history entries
   */
  findRecentByUserId(userId: string, limit: number): Promise<PasswordHistory[]>;

  /**
   * Check if a password hash exists in user's history
   * @param userId The user ID
   * @param passwordHash The password hash to check
   * @returns True if the password hash exists in the user's history, false otherwise
   */
  isPasswordHashInHistory(userId: string, passwordHash: string): Promise<boolean>;

  /**
   * Delete password history entries older than a certain date for a user
   * @param userId The user ID
   * @param date The date threshold
   * @returns The number of deleted entries
   */
  deleteOlderThan(userId: string, date: Date): Promise<number>;
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
   * Maps a Prisma password history to a domain model password history
   * @param prismaPasswordHistory The Prisma password history
   * @returns The domain model password history
   */
  protected mapToDomainModel(prismaPasswordHistory: PrismaPasswordHistory): PasswordHistory {
    return {
      id: prismaPasswordHistory.id,
      userId: prismaPasswordHistory.userId,
      credentialId: prismaPasswordHistory.credentialId,
      passwordHash: prismaPasswordHistory.passwordHash,
      createdAt: prismaPasswordHistory.createdAt,
    };
  }

  /**
   * Find password history entries by user ID
   * @param userId The user ID
   * @param options Optional query options
   * @returns Array of password history entries
   */
  async findByUserId(userId: string, options?: QueryOptions): Promise<PasswordHistory[]> {
    try {
      const prismaOptions = this.toPrismaOptions(options);
      const passwordHistories = await this.prisma.passwordHistory.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        ...prismaOptions,
      });

      return passwordHistories.map(history => this.mapToDomainModel(history));
    } catch (error) {
      logger.error('Error finding password history by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding password history by user ID',
        'PASSWORD_HISTORY_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find password history entries by credential ID
   * @param credentialId The credential ID
   * @param options Optional query options
   * @returns Array of password history entries
   */
  async findByCredentialId(
    credentialId: string,
    options?: QueryOptions
  ): Promise<PasswordHistory[]> {
    try {
      const prismaOptions = this.toPrismaOptions(options);
      const passwordHistories = await this.prisma.passwordHistory.findMany({
        where: { credentialId },
        orderBy: { createdAt: 'desc' },
        ...prismaOptions,
      });

      return passwordHistories.map(history => this.mapToDomainModel(history));
    } catch (error) {
      logger.error('Error finding password history by credential ID', { credentialId, error });
      throw new DatabaseError(
        'Error finding password history by credential ID',
        'PASSWORD_HISTORY_FIND_BY_CREDENTIAL_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find password history entries by user ID and credential ID
   * @param userId The user ID
   * @param credentialId The credential ID
   * @param options Optional query options
   * @returns Array of password history entries
   */
  async findByUserIdAndCredentialId(
    userId: string,
    credentialId: string,
    options?: QueryOptions
  ): Promise<PasswordHistory[]> {
    try {
      const prismaOptions = this.toPrismaOptions(options);
      const passwordHistories = await this.prisma.passwordHistory.findMany({
        where: {
          userId,
          credentialId,
        },
        orderBy: { createdAt: 'desc' },
        ...prismaOptions,
      });

      return passwordHistories.map(history => this.mapToDomainModel(history));
    } catch (error) {
      logger.error('Error finding password history by user ID and credential ID', {
        userId,
        credentialId,
        error,
      });
      throw new DatabaseError(
        'Error finding password history by user ID and credential ID',
        'PASSWORD_HISTORY_FIND_BY_USER_ID_AND_CREDENTIAL_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find recent password history entries by user ID
   * @param userId The user ID
   * @param limit The maximum number of entries to return
   * @returns Array of password history entries
   */
  async findRecentByUserId(userId: string, limit: number): Promise<PasswordHistory[]> {
    try {
      const passwordHistories = await this.prisma.passwordHistory.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        take: limit,
      });

      return passwordHistories.map(history => this.mapToDomainModel(history));
    } catch (error) {
      logger.error('Error finding recent password history by user ID', { userId, limit, error });
      throw new DatabaseError(
        'Error finding recent password history by user ID',
        'PASSWORD_HISTORY_FIND_RECENT_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check if a password hash exists in user's history
   * @param userId The user ID
   * @param passwordHash The password hash to check
   * @returns True if the password hash exists in the user's history, false otherwise
   */
  async isPasswordHashInHistory(userId: string, passwordHash: string): Promise<boolean> {
    try {
      const count = await this.prisma.passwordHistory.count({
        where: {
          userId,
          passwordHash,
        },
      });

      return count > 0;
    } catch (error) {
      logger.error('Error checking if password hash is in history', { userId, error });
      throw new DatabaseError(
        'Error checking if password hash is in history',
        'PASSWORD_HISTORY_CHECK_HASH_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete password history entries older than a certain date for a user
   * @param userId The user ID
   * @param date The date threshold
   * @returns The number of deleted entries
   */
  async deleteOlderThan(userId: string, date: Date): Promise<number> {
    try {
      const result = await this.prisma.passwordHistory.deleteMany({
        where: {
          userId,
          createdAt: {
            lt: date,
          },
        },
      });

      return result.count;
    } catch (error) {
      logger.error('Error deleting password history older than date', { userId, date, error });
      throw new DatabaseError(
        'Error deleting password history older than date',
        'PASSWORD_HISTORY_DELETE_OLDER_THAN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Create a new password history entry
   * @param data The password history data
   * @returns The created password history entry
   */
  override async create(data: CreatePasswordHistoryData): Promise<PasswordHistory> {
    try {
      const passwordHistory = await this.prisma.passwordHistory.create({
        data: {
          userId: data.userId,
          credentialId: data.credentialId,
          passwordHash: data.passwordHash,
        },
      });

      return this.mapToDomainModel(passwordHistory);
    } catch (error) {
      logger.error('Error creating password history', { data, error });
      throw new DatabaseError(
        'Error creating password history',
        'PASSWORD_HISTORY_CREATE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find password history entries by filter options
   * @param filter The filter options
   * @param options Optional query options
   * @returns Array of password history entries
   */
  override async findBy(
    filter: PasswordHistoryFilterOptions,
    options?: QueryOptions
  ): Promise<PasswordHistory[]> {
    try {
      const where: Prisma.PasswordHistoryWhereInput = {};

      if (filter.id) {
        where.id = filter.id;
      }

      if (filter.userId) {
        where.userId = filter.userId;
      }

      if (filter.credentialId) {
        where.credentialId = filter.credentialId;
      }

      if (filter.createdAtBefore) {
        where.createdAt = {
          ...((where.createdAt as any) || {}),
          lt: filter.createdAtBefore,
        };
      }

      if (filter.createdAtAfter) {
        where.createdAt = {
          ...((where.createdAt as any) || {}),
          gt: filter.createdAtAfter,
        };
      }

      const prismaOptions = this.toPrismaOptions(options);
      const passwordHistories = await this.prisma.passwordHistory.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        ...prismaOptions,
      });

      return passwordHistories.map(history => this.mapToDomainModel(history));
    } catch (error) {
      logger.error('Error finding password history by filter', { filter, error });
      throw new DatabaseError(
        'Error finding password history by filter',
        'PASSWORD_HISTORY_FIND_BY_FILTER_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected withTransaction(tx: TransactionClient): BaseRepository<PasswordHistory, string> {
    return new PrismaPasswordHistoryRepository(tx);
  }
}

// Export a singleton instance
export const passwordHistoryRepository = new PrismaPasswordHistoryRepository();
