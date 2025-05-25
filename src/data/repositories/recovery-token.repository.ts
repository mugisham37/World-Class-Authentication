import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  RecoveryToken,
  RecoveryTokenType,
  RecoveryTokenFilterOptions,
} from '../models/recovery-token.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * Recovery token repository interface
 * Defines recovery token-specific operations
 */
export interface RecoveryTokenRepository extends BaseRepository<RecoveryToken, string> {
  /**
   * Find a recovery token by token string
   * @param token Token string
   * @returns Recovery token or null if not found
   */
  findByToken(token: string): Promise<RecoveryToken | null>;

  /**
   * Find recovery tokens by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns List of recovery tokens
   */
  findByUserId(userId: string, options?: RecoveryTokenFilterOptions): Promise<RecoveryToken[]>;

  /**
   * Find recovery tokens by email
   * @param email Email
   * @param options Filter options
   * @returns List of recovery tokens
   */
  findByEmail(email: string, options?: RecoveryTokenFilterOptions): Promise<RecoveryToken[]>;

  /**
   * Find active recovery tokens by user ID and type
   * @param userId User ID
   * @param type Recovery token type
   * @returns List of active recovery tokens
   */
  findActiveByUserIdAndType(userId: string, type: RecoveryTokenType): Promise<RecoveryToken[]>;

  /**
   * Find active recovery tokens by email and type
   * @param email Email
   * @param type Recovery token type
   * @returns List of active recovery tokens
   */
  findActiveByEmailAndType(email: string, type: RecoveryTokenType): Promise<RecoveryToken[]>;

  /**
   * Mark a recovery token as used
   * @param id Recovery token ID
   * @returns Updated recovery token
   */
  markAsUsed(id: string): Promise<RecoveryToken>;

  /**
   * Mark a recovery token as used by token string
   * @param token Token string
   * @returns Updated recovery token
   */
  markAsUsedByToken(token: string): Promise<RecoveryToken>;

  /**
   * Verify a recovery token
   * @param token Token string
   * @returns Recovery token if valid, null otherwise
   */
  verifyToken(token: string): Promise<RecoveryToken | null>;

  /**
   * Delete expired recovery tokens
   * @returns Number of deleted tokens
   */
  deleteExpired(): Promise<number>;

  /**
   * Delete recovery tokens by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns Number of deleted tokens
   */
  deleteByUserId(userId: string, options?: RecoveryTokenFilterOptions): Promise<number>;

  /**
   * Delete recovery tokens by email
   * @param email Email
   * @param options Filter options
   * @returns Number of deleted tokens
   */
  deleteByEmail(email: string, options?: RecoveryTokenFilterOptions): Promise<number>;

  /**
   * Delete used recovery tokens
   * @returns Number of deleted tokens
   */
  deleteUsed(): Promise<number>;
}

/**
 * Prisma implementation of the recovery token repository
 */
export class PrismaRecoveryTokenRepository
  extends PrismaBaseRepository<RecoveryToken, string>
  implements RecoveryTokenRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'recoveryToken';

  /**
   * Find a recovery token by token string
   * @param token Token string
   * @returns Recovery token or null if not found
   */
  async findByToken(token: string): Promise<RecoveryToken | null> {
    try {
      const recoveryToken = await this.prisma.recoveryToken.findUnique({
        where: { token },
      });
      return recoveryToken;
    } catch (error) {
      logger.error('Error finding recovery token by token string', { token, error });
      throw new DatabaseError(
        'Error finding recovery token by token string',
        'RECOVERY_TOKEN_FIND_BY_TOKEN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find recovery tokens by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns List of recovery tokens
   */
  async findByUserId(
    userId: string,
    options?: RecoveryTokenFilterOptions
  ): Promise<RecoveryToken[]> {
    try {
      const where = this.buildWhereClause({ ...options, userId });
      const tokens = await this.prisma.recoveryToken.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return tokens;
    } catch (error) {
      logger.error('Error finding recovery tokens by user ID', { userId, options, error });
      throw new DatabaseError(
        'Error finding recovery tokens by user ID',
        'RECOVERY_TOKEN_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find recovery tokens by email
   * @param email Email
   * @param options Filter options
   * @returns List of recovery tokens
   */
  async findByEmail(email: string, options?: RecoveryTokenFilterOptions): Promise<RecoveryToken[]> {
    try {
      const where = this.buildWhereClause({ ...options, email });
      const tokens = await this.prisma.recoveryToken.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return tokens;
    } catch (error) {
      logger.error('Error finding recovery tokens by email', { email, options, error });
      throw new DatabaseError(
        'Error finding recovery tokens by email',
        'RECOVERY_TOKEN_FIND_BY_EMAIL_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find active recovery tokens by user ID and type
   * @param userId User ID
   * @param type Recovery token type
   * @returns List of active recovery tokens
   */
  async findActiveByUserIdAndType(
    userId: string,
    type: RecoveryTokenType
  ): Promise<RecoveryToken[]> {
    try {
      const now = new Date();
      const tokens = await this.prisma.recoveryToken.findMany({
        where: {
          userId,
          type,
          expiresAt: { gt: now },
          usedAt: null,
        },
        orderBy: { createdAt: 'desc' },
      });
      return tokens;
    } catch (error) {
      logger.error('Error finding active recovery tokens by user ID and type', {
        userId,
        type,
        error,
      });
      throw new DatabaseError(
        'Error finding active recovery tokens by user ID and type',
        'RECOVERY_TOKEN_FIND_ACTIVE_BY_USER_ID_AND_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find active recovery tokens by email and type
   * @param email Email
   * @param type Recovery token type
   * @returns List of active recovery tokens
   */
  async findActiveByEmailAndType(email: string, type: RecoveryTokenType): Promise<RecoveryToken[]> {
    try {
      const now = new Date();
      const tokens = await this.prisma.recoveryToken.findMany({
        where: {
          email,
          type,
          expiresAt: { gt: now },
          usedAt: null,
        },
        orderBy: { createdAt: 'desc' },
      });
      return tokens;
    } catch (error) {
      logger.error('Error finding active recovery tokens by email and type', {
        email,
        type,
        error,
      });
      throw new DatabaseError(
        'Error finding active recovery tokens by email and type',
        'RECOVERY_TOKEN_FIND_ACTIVE_BY_EMAIL_AND_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Mark a recovery token as used
   * @param id Recovery token ID
   * @returns Updated recovery token
   */
  async markAsUsed(id: string): Promise<RecoveryToken> {
    try {
      const token = await this.prisma.recoveryToken.update({
        where: { id },
        data: {
          usedAt: new Date(),
        },
      });
      return token;
    } catch (error) {
      logger.error('Error marking recovery token as used', { id, error });
      throw new DatabaseError(
        'Error marking recovery token as used',
        'RECOVERY_TOKEN_MARK_AS_USED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Mark a recovery token as used by token string
   * @param token Token string
   * @returns Updated recovery token
   */
  async markAsUsedByToken(token: string): Promise<RecoveryToken> {
    try {
      const updatedToken = await this.prisma.recoveryToken.update({
        where: { token },
        data: {
          usedAt: new Date(),
        },
      });
      return updatedToken;
    } catch (error) {
      logger.error('Error marking recovery token as used by token string', { token, error });
      throw new DatabaseError(
        'Error marking recovery token as used by token string',
        'RECOVERY_TOKEN_MARK_AS_USED_BY_TOKEN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Verify a recovery token
   * @param token Token string
   * @returns Recovery token if valid, null otherwise
   */
  async verifyToken(token: string): Promise<RecoveryToken | null> {
    try {
      const now = new Date();
      const recoveryToken = await this.prisma.recoveryToken.findFirst({
        where: {
          token,
          expiresAt: { gt: now },
          usedAt: null,
        },
      });
      return recoveryToken;
    } catch (error) {
      logger.error('Error verifying recovery token', { token, error });
      throw new DatabaseError(
        'Error verifying recovery token',
        'RECOVERY_TOKEN_VERIFY_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete expired recovery tokens
   * @returns Number of deleted tokens
   */
  async deleteExpired(): Promise<number> {
    try {
      const now = new Date();
      const result = await this.prisma.recoveryToken.deleteMany({
        where: {
          expiresAt: { lt: now },
          usedAt: null,
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting expired recovery tokens', { error });
      throw new DatabaseError(
        'Error deleting expired recovery tokens',
        'RECOVERY_TOKEN_DELETE_EXPIRED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete recovery tokens by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns Number of deleted tokens
   */
  async deleteByUserId(userId: string, options?: RecoveryTokenFilterOptions): Promise<number> {
    try {
      const where = this.buildWhereClause({ ...options, userId });
      const result = await this.prisma.recoveryToken.deleteMany({
        where,
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting recovery tokens by user ID', { userId, options, error });
      throw new DatabaseError(
        'Error deleting recovery tokens by user ID',
        'RECOVERY_TOKEN_DELETE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete recovery tokens by email
   * @param email Email
   * @param options Filter options
   * @returns Number of deleted tokens
   */
  async deleteByEmail(email: string, options?: RecoveryTokenFilterOptions): Promise<number> {
    try {
      const where = this.buildWhereClause({ ...options, email });
      const result = await this.prisma.recoveryToken.deleteMany({
        where,
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting recovery tokens by email', { email, options, error });
      throw new DatabaseError(
        'Error deleting recovery tokens by email',
        'RECOVERY_TOKEN_DELETE_BY_EMAIL_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete used recovery tokens
   * @returns Number of deleted tokens
   */
  async deleteUsed(): Promise<number> {
    try {
      const result = await this.prisma.recoveryToken.deleteMany({
        where: {
          usedAt: { not: null },
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting used recovery tokens', { error });
      throw new DatabaseError(
        'Error deleting used recovery tokens',
        'RECOVERY_TOKEN_DELETE_USED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  private buildWhereClause(filter?: RecoveryTokenFilterOptions): any {
    if (!filter) {
      return {};
    }

    const where: any = {};

    if (filter.id) {
      where.id = filter.id;
    }

    if (filter.token) {
      where.token = filter.token;
    }

    if (filter.type) {
      where.type = filter.type;
    }

    if (filter.userId) {
      where.userId = filter.userId;
    }

    if (filter.email) {
      where.email = filter.email;
    }

    // Boolean filters
    if (filter.isUsed !== undefined) {
      if (filter.isUsed) {
        where.usedAt = { not: null };
      } else {
        where.usedAt = null;
      }
    }

    if (filter.isExpired !== undefined) {
      const now = new Date();
      if (filter.isExpired) {
        where.expiresAt = { lt: now };
      } else {
        where.expiresAt = { gte: now };
      }
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

    if (filter.expiresAtBefore || filter.expiresAtAfter) {
      where.expiresAt = where.expiresAt || {};

      if (filter.expiresAtBefore) {
        where.expiresAt.lte = filter.expiresAtBefore;
      }

      if (filter.expiresAtAfter) {
        where.expiresAt.gte = filter.expiresAtAfter;
      }
    }

    if (filter.usedAtBefore || filter.usedAtAfter) {
      where.usedAt = where.usedAt || {};

      if (filter.usedAtBefore) {
        where.usedAt.lte = filter.usedAtBefore;
      }

      if (filter.usedAtAfter) {
        where.usedAt.gte = filter.usedAtAfter;
      }
    }

    return where;
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected withTransaction(tx: PrismaClient): BaseRepository<RecoveryToken, string> {
    return new PrismaRecoveryTokenRepository(tx);
  }
}

// Export a singleton instance
export const recoveryTokenRepository = new PrismaRecoveryTokenRepository();
