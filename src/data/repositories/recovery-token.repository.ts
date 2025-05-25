import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  RecoveryToken,
  RecoveryTokenType,
  CreateRecoveryTokenData,
  UpdateRecoveryTokenData,
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
   * Find a recovery token by token value
   * @param token The token value
   * @returns The recovery token or null if not found
   */
  findByToken(token: string): Promise<RecoveryToken | null>;

  /**
   * Find recovery tokens by user ID
   * @param userId The user ID
   * @returns Array of recovery tokens
   */
  findByUserId(userId: string): Promise<RecoveryToken[]>;

  /**
   * Find recovery tokens by email
   * @param email The email
   * @returns Array of recovery tokens
   */
  findByEmail(email: string): Promise<RecoveryToken[]>;

  /**
   * Find active recovery tokens by user ID and type
   * @param userId The user ID
   * @param type The recovery token type
   * @returns Array of active recovery tokens
   */
  findActiveByUserIdAndType(userId: string, type: RecoveryTokenType): Promise<RecoveryToken[]>;

  /**
   * Find active recovery tokens by email and type
   * @param email The email
   * @param type The recovery token type
   * @returns Array of active recovery tokens
   */
  findActiveByEmailAndType(email: string, type: RecoveryTokenType): Promise<RecoveryToken[]>;

  /**
   * Mark a recovery token as used
   * @param id The recovery token ID
   * @returns The updated recovery token
   */
  markAsUsed(id: string): Promise<RecoveryToken>;

  /**
   * Mark a recovery token as used by token value
   * @param token The token value
   * @returns The updated recovery token or null if not found
   */
  markAsUsedByToken(token: string): Promise<RecoveryToken | null>;

  /**
   * Verify a recovery token
   * @param token The token value
   * @param type The expected token type
   * @returns The recovery token if valid, null otherwise
   */
  verifyToken(token: string, type: RecoveryTokenType): Promise<RecoveryToken | null>;

  /**
   * Delete expired recovery tokens
   * @returns Number of deleted recovery tokens
   */
  deleteExpired(): Promise<number>;

  /**
   * Delete recovery tokens by user ID
   * @param userId The user ID
   * @returns Number of deleted recovery tokens
   */
  deleteByUserId(userId: string): Promise<number>;

  /**
   * Delete recovery tokens by email
   * @param email The email
   * @returns Number of deleted recovery tokens
   */
  deleteByEmail(email: string): Promise<number>;

  /**
   * Delete used recovery tokens
   * @returns Number of deleted recovery tokens
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
   * Find a recovery token by token value
   * @param token The token value
   * @returns The recovery token or null if not found
   */
  async findByToken(token: string): Promise<RecoveryToken | null> {
    try {
      const recoveryToken = await this.prisma.recoveryToken.findUnique({
        where: { token },
      });
      return recoveryToken;
    } catch (error) {
      logger.error('Error finding recovery token by token value', { token, error });
      throw new DatabaseError(
        'Error finding recovery token by token value',
        'RECOVERY_TOKEN_FIND_BY_TOKEN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find recovery tokens by user ID
   * @param userId The user ID
   * @returns Array of recovery tokens
   */
  async findByUserId(userId: string): Promise<RecoveryToken[]> {
    try {
      const tokens = await this.prisma.recoveryToken.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
      });
      return tokens;
    } catch (error) {
      logger.error('Error finding recovery tokens by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding recovery tokens by user ID',
        'RECOVERY_TOKEN_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find recovery tokens by email
   * @param email The email
   * @returns Array of recovery tokens
   */
  async findByEmail(email: string): Promise<RecoveryToken[]> {
    try {
      const tokens = await this.prisma.recoveryToken.findMany({
        where: { email },
        orderBy: { createdAt: 'desc' },
      });
      return tokens;
    } catch (error) {
      logger.error('Error finding recovery tokens by email', { email, error });
      throw new DatabaseError(
        'Error finding recovery tokens by email',
        'RECOVERY_TOKEN_FIND_BY_EMAIL_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find active recovery tokens by user ID and type
   * @param userId The user ID
   * @param type The recovery token type
   * @returns Array of active recovery tokens
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
          usedAt: null,
          expiresAt: {
            gt: now,
          },
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
   * @param email The email
   * @param type The recovery token type
   * @returns Array of active recovery tokens
   */
  async findActiveByEmailAndType(email: string, type: RecoveryTokenType): Promise<RecoveryToken[]> {
    try {
      const now = new Date();
      const tokens = await this.prisma.recoveryToken.findMany({
        where: {
          email,
          type,
          usedAt: null,
          expiresAt: {
            gt: now,
          },
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
   * @param id The recovery token ID
   * @returns The updated recovery token
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
   * Mark a recovery token as used by token value
   * @param token The token value
   * @returns The updated recovery token or null if not found
   */
  async markAsUsedByToken(token: string): Promise<RecoveryToken | null> {
    try {
      const recoveryToken = await this.prisma.recoveryToken.findUnique({
        where: { token },
      });

      if (!recoveryToken) {
        return null;
      }

      return await this.markAsUsed(recoveryToken.id);
    } catch (error) {
      logger.error('Error marking recovery token as used by token value', { token, error });
      throw new DatabaseError(
        'Error marking recovery token as used by token value',
        'RECOVERY_TOKEN_MARK_AS_USED_BY_TOKEN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Verify a recovery token
   * @param token The token value
   * @param type The expected token type
   * @returns The recovery token if valid, null otherwise
   */
  async verifyToken(token: string, type: RecoveryTokenType): Promise<RecoveryToken | null> {
    try {
      const now = new Date();
      const recoveryToken = await this.prisma.recoveryToken.findFirst({
        where: {
          token,
          type,
          usedAt: null,
          expiresAt: {
            gt: now,
          },
        },
      });

      return recoveryToken;
    } catch (error) {
      logger.error('Error verifying recovery token', { token, type, error });
      throw new DatabaseError(
        'Error verifying recovery token',
        'RECOVERY_TOKEN_VERIFY_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete expired recovery tokens
   * @returns Number of deleted recovery tokens
   */
  async deleteExpired(): Promise<number> {
    try {
      const now = new Date();
      const result = await this.prisma.recoveryToken.deleteMany({
        where: {
          expiresAt: {
            lt: now,
          },
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
   * @param userId The user ID
   * @returns Number of deleted recovery tokens
   */
  async deleteByUserId(userId: string): Promise<number> {
    try {
      const result = await this.prisma.recoveryToken.deleteMany({
        where: { userId },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting recovery tokens by user ID', { userId, error });
      throw new DatabaseError(
        'Error deleting recovery tokens by user ID',
        'RECOVERY_TOKEN_DELETE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete recovery tokens by email
   * @param email The email
   * @returns Number of deleted recovery tokens
   */
  async deleteByEmail(email: string): Promise<number> {
    try {
      const result = await this.prisma.recoveryToken.deleteMany({
        where: { email },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting recovery tokens by email', { email, error });
      throw new DatabaseError(
        'Error deleting recovery tokens by email',
        'RECOVERY_TOKEN_DELETE_BY_EMAIL_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete used recovery tokens
   * @returns Number of deleted recovery tokens
   */
  async deleteUsed(): Promise<number> {
    try {
      const result = await this.prisma.recoveryToken.deleteMany({
        where: {
          usedAt: {
            not: null,
          },
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
  protected override toWhereClause(filter?: RecoveryTokenFilterOptions): any {
    if (!filter) {
      return {};
    }

    const where: any = {};
    const now = new Date();

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

    if (filter.isUsed !== undefined) {
      if (filter.isUsed) {
        where.usedAt = {
          not: null,
        };
      } else {
        where.usedAt = null;
      }
    }

    if (filter.isExpired !== undefined) {
      if (filter.isExpired) {
        where.expiresAt = {
          lt: now,
        };
      } else {
        where.expiresAt = {
          gte: now,
        };
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
  protected override withTransaction(tx: PrismaClient): BaseRepository<RecoveryToken, string> {
    return new PrismaRecoveryTokenRepository(tx);
  }
}

// Export a singleton instance
export const recoveryTokenRepository = new PrismaRecoveryTokenRepository();
