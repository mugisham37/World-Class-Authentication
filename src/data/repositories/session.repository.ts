import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  Session,
  CreateSessionData,
  UpdateSessionData,
  SessionFilterOptions,
} from '../models/session.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * Session repository interface
 * Defines session-specific operations
 */
export interface SessionRepository extends BaseRepository<Session, string> {
  /**
   * Find a session by token
   * @param token The session token
   * @returns The session or null if not found
   */
  findByToken(token: string): Promise<Session | null>;

  /**
   * Find a session by refresh token
   * @param refreshToken The refresh token
   * @returns The session or null if not found
   */
  findByRefreshToken(refreshToken: string): Promise<Session | null>;

  /**
   * Find sessions by user ID
   * @param userId The user ID
   * @returns Array of sessions
   */
  findByUserId(userId: string): Promise<Session[]>;

  /**
   * Find active sessions by user ID
   * @param userId The user ID
   * @returns Array of active sessions
   */
  findActiveByUserId(userId: string): Promise<Session[]>;

  /**
   * Find sessions by device ID
   * @param deviceId The device ID
   * @returns Array of sessions
   */
  findByDeviceId(deviceId: string): Promise<Session[]>;

  /**
   * Update a session's last active time
   * @param id The session ID
   * @returns The updated session
   */
  updateLastActive(id: string): Promise<Session>;

  /**
   * Update a session's last active time by token
   * @param token The session token
   * @returns The updated session or null if not found
   */
  updateLastActiveByToken(token: string): Promise<Session | null>;

  /**
   * Revoke a session
   * @param id The session ID
   * @param reason The revocation reason
   * @returns The updated session
   */
  revoke(id: string, reason?: string): Promise<Session>;

  /**
   * Revoke a session by token
   * @param token The session token
   * @param reason The revocation reason
   * @returns The updated session or null if not found
   */
  revokeByToken(token: string, reason?: string): Promise<Session | null>;

  /**
   * Revoke all sessions for a user
   * @param userId The user ID
   * @param reason The revocation reason
   * @returns Number of revoked sessions
   */
  revokeAllForUser(userId: string, reason?: string): Promise<number>;

  /**
   * Revoke all sessions for a user except the current one
   * @param userId The user ID
   * @param currentSessionId The current session ID to exclude
   * @param reason The revocation reason
   * @returns Number of revoked sessions
   */
  revokeAllForUserExceptCurrent(
    userId: string,
    currentSessionId: string,
    reason?: string
  ): Promise<number>;

  /**
   * Delete expired sessions
   * @returns Number of deleted sessions
   */
  deleteExpired(): Promise<number>;

  /**
   * Delete revoked sessions
   * @returns Number of deleted sessions
   */
  deleteRevoked(): Promise<number>;

  /**
   * Count active sessions for a user
   * @param userId The user ID
   * @returns Number of active sessions
   */
  countActiveByUserId(userId: string): Promise<number>;

  /**
   * Check if a session is active
   * @param id The session ID
   * @returns True if the session is active, false otherwise
   */
  isActive(id: string): Promise<boolean>;

  /**
   * Check if a session is active by token
   * @param token The session token
   * @returns True if the session is active, false otherwise
   */
  isActiveByToken(token: string): Promise<boolean>;
}

/**
 * Prisma implementation of the session repository
 */
export class PrismaSessionRepository
  extends PrismaBaseRepository<Session, string>
  implements SessionRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'session';

  /**
   * Find a session by token
   * @param token The session token
   * @returns The session or null if not found
   */
  async findByToken(token: string): Promise<Session | null> {
    try {
      const session = await this.prisma.session.findUnique({
        where: { token },
      });
      return session;
    } catch (error) {
      logger.error('Error finding session by token', { error });
      throw new DatabaseError(
        'Error finding session by token',
        'SESSION_FIND_BY_TOKEN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find a session by refresh token
   * @param refreshToken The refresh token
   * @returns The session or null if not found
   */
  async findByRefreshToken(refreshToken: string): Promise<Session | null> {
    try {
      const session = await this.prisma.session.findUnique({
        where: { refreshToken },
      });
      return session;
    } catch (error) {
      logger.error('Error finding session by refresh token', { error });
      throw new DatabaseError(
        'Error finding session by refresh token',
        'SESSION_FIND_BY_REFRESH_TOKEN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find sessions by user ID
   * @param userId The user ID
   * @returns Array of sessions
   */
  async findByUserId(userId: string): Promise<Session[]> {
    try {
      const sessions = await this.prisma.session.findMany({
        where: { userId },
        orderBy: { lastActiveAt: 'desc' },
      });
      return sessions;
    } catch (error) {
      logger.error('Error finding sessions by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding sessions by user ID',
        'SESSION_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find active sessions by user ID
   * @param userId The user ID
   * @returns Array of active sessions
   */
  async findActiveByUserId(userId: string): Promise<Session[]> {
    try {
      const now = new Date();
      const sessions = await this.prisma.session.findMany({
        where: {
          userId,
          expiresAt: { gt: now },
          revokedAt: null,
        },
        orderBy: { lastActiveAt: 'desc' },
      });
      return sessions;
    } catch (error) {
      logger.error('Error finding active sessions by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding active sessions by user ID',
        'SESSION_FIND_ACTIVE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find sessions by device ID
   * @param deviceId The device ID
   * @returns Array of sessions
   */
  async findByDeviceId(deviceId: string): Promise<Session[]> {
    try {
      const sessions = await this.prisma.session.findMany({
        where: { deviceId },
        orderBy: { lastActiveAt: 'desc' },
      });
      return sessions;
    } catch (error) {
      logger.error('Error finding sessions by device ID', { deviceId, error });
      throw new DatabaseError(
        'Error finding sessions by device ID',
        'SESSION_FIND_BY_DEVICE_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update a session's last active time
   * @param id The session ID
   * @returns The updated session
   */
  async updateLastActive(id: string): Promise<Session> {
    try {
      const session = await this.prisma.session.update({
        where: { id },
        data: {
          lastActiveAt: new Date(),
        },
      });
      return session;
    } catch (error) {
      logger.error('Error updating session last active time', { id, error });
      throw new DatabaseError(
        'Error updating session last active time',
        'SESSION_UPDATE_LAST_ACTIVE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update a session's last active time by token
   * @param token The session token
   * @returns The updated session or null if not found
   */
  async updateLastActiveByToken(token: string): Promise<Session | null> {
    try {
      const session = await this.prisma.session.findUnique({
        where: { token },
      });

      if (!session) {
        return null;
      }

      return await this.updateLastActive(session.id);
    } catch (error) {
      logger.error('Error updating session last active time by token', { token, error });
      throw new DatabaseError(
        'Error updating session last active time by token',
        'SESSION_UPDATE_LAST_ACTIVE_BY_TOKEN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Revoke a session
   * @param id The session ID
   * @param reason The revocation reason
   * @returns The updated session
   */
  async revoke(id: string, reason?: string): Promise<Session> {
    try {
      const session = await this.prisma.session.update({
        where: { id },
        data: {
          revokedAt: new Date(),
          revocationReason: reason,
        },
      });
      return session;
    } catch (error) {
      logger.error('Error revoking session', { id, error });
      throw new DatabaseError(
        'Error revoking session',
        'SESSION_REVOKE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Revoke a session by token
   * @param token The session token
   * @param reason The revocation reason
   * @returns The updated session or null if not found
   */
  async revokeByToken(token: string, reason?: string): Promise<Session | null> {
    try {
      const session = await this.prisma.session.findUnique({
        where: { token },
      });

      if (!session) {
        return null;
      }

      return await this.revoke(session.id, reason);
    } catch (error) {
      logger.error('Error revoking session by token', { token, error });
      throw new DatabaseError(
        'Error revoking session by token',
        'SESSION_REVOKE_BY_TOKEN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Revoke all sessions for a user
   * @param userId The user ID
   * @param reason The revocation reason
   * @returns Number of revoked sessions
   */
  async revokeAllForUser(userId: string, reason?: string): Promise<number> {
    try {
      const now = new Date();
      const result = await this.prisma.session.updateMany({
        where: {
          userId,
          revokedAt: null,
        },
        data: {
          revokedAt: now,
          revocationReason: reason,
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error revoking all sessions for user', { userId, error });
      throw new DatabaseError(
        'Error revoking all sessions for user',
        'SESSION_REVOKE_ALL_FOR_USER_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Revoke all sessions for a user except the current one
   * @param userId The user ID
   * @param currentSessionId The current session ID to exclude
   * @param reason The revocation reason
   * @returns Number of revoked sessions
   */
  async revokeAllForUserExceptCurrent(
    userId: string,
    currentSessionId: string,
    reason?: string
  ): Promise<number> {
    try {
      const now = new Date();
      const result = await this.prisma.session.updateMany({
        where: {
          userId,
          id: { not: currentSessionId },
          revokedAt: null,
        },
        data: {
          revokedAt: now,
          revocationReason: reason,
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error revoking all sessions for user except current', {
        userId,
        currentSessionId,
        error,
      });
      throw new DatabaseError(
        'Error revoking all sessions for user except current',
        'SESSION_REVOKE_ALL_FOR_USER_EXCEPT_CURRENT_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete expired sessions
   * @returns Number of deleted sessions
   */
  async deleteExpired(): Promise<number> {
    try {
      const now = new Date();
      const result = await this.prisma.session.deleteMany({
        where: {
          expiresAt: { lt: now },
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting expired sessions', { error });
      throw new DatabaseError(
        'Error deleting expired sessions',
        'SESSION_DELETE_EXPIRED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete revoked sessions
   * @returns Number of deleted sessions
   */
  async deleteRevoked(): Promise<number> {
    try {
      const result = await this.prisma.session.deleteMany({
        where: {
          revokedAt: { not: null },
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting revoked sessions', { error });
      throw new DatabaseError(
        'Error deleting revoked sessions',
        'SESSION_DELETE_REVOKED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count active sessions for a user
   * @param userId The user ID
   * @returns Number of active sessions
   */
  async countActiveByUserId(userId: string): Promise<number> {
    try {
      const now = new Date();
      const count = await this.prisma.session.count({
        where: {
          userId,
          expiresAt: { gt: now },
          revokedAt: null,
        },
      });
      return count;
    } catch (error) {
      logger.error('Error counting active sessions by user ID', { userId, error });
      throw new DatabaseError(
        'Error counting active sessions by user ID',
        'SESSION_COUNT_ACTIVE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check if a session is active
   * @param id The session ID
   * @returns True if the session is active, false otherwise
   */
  async isActive(id: string): Promise<boolean> {
    try {
      const now = new Date();
      const count = await this.prisma.session.count({
        where: {
          id,
          expiresAt: { gt: now },
          revokedAt: null,
        },
      });
      return count > 0;
    } catch (error) {
      logger.error('Error checking if session is active', { id, error });
      throw new DatabaseError(
        'Error checking if session is active',
        'SESSION_IS_ACTIVE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check if a session is active by token
   * @param token The session token
   * @returns True if the session is active, false otherwise
   */
  async isActiveByToken(token: string): Promise<boolean> {
    try {
      const now = new Date();
      const count = await this.prisma.session.count({
        where: {
          token,
          expiresAt: { gt: now },
          revokedAt: null,
        },
      });
      return count > 0;
    } catch (error) {
      logger.error('Error checking if session is active by token', { token, error });
      throw new DatabaseError(
        'Error checking if session is active by token',
        'SESSION_IS_ACTIVE_BY_TOKEN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  protected override toWhereClause(filter?: SessionFilterOptions): any {
    if (!filter) {
      return {};
    }

    const where: any = {};
    const now = new Date();

    if (filter.id) {
      where.id = filter.id;
    }

    if (filter.userId) {
      where.userId = filter.userId;
    }

    if (filter.token) {
      where.token = filter.token;
    }

    if (filter.refreshToken) {
      where.refreshToken = filter.refreshToken;
    }

    if (filter.deviceId) {
      where.deviceId = filter.deviceId;
    }

    if (filter.ipAddress) {
      where.ipAddress = filter.ipAddress;
    }

    if (filter.isActive !== undefined) {
      if (filter.isActive) {
        where.expiresAt = { gt: now };
        where.revokedAt = null;
      } else {
        where.OR = [{ expiresAt: { lte: now } }, { revokedAt: { not: null } }];
      }
    }

    if (filter.isRevoked !== undefined) {
      if (filter.isRevoked) {
        where.revokedAt = { not: null };
      } else {
        where.revokedAt = null;
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

    if (filter.updatedAtBefore || filter.updatedAtAfter) {
      where.updatedAt = {};

      if (filter.updatedAtBefore) {
        where.updatedAt.lte = filter.updatedAtBefore;
      }

      if (filter.updatedAtAfter) {
        where.updatedAt.gte = filter.updatedAtAfter;
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

    if (filter.lastActiveAtBefore || filter.lastActiveAtAfter) {
      where.lastActiveAt = {};

      if (filter.lastActiveAtBefore) {
        where.lastActiveAt.lte = filter.lastActiveAtBefore;
      }

      if (filter.lastActiveAtAfter) {
        where.lastActiveAt.gte = filter.lastActiveAtAfter;
      }
    }

    if (filter.revokedAtBefore || filter.revokedAtAfter) {
      where.revokedAt = where.revokedAt || {};

      if (filter.revokedAtBefore) {
        where.revokedAt.lte = filter.revokedAtBefore;
      }

      if (filter.revokedAtAfter) {
        where.revokedAt.gte = filter.revokedAtAfter;
      }
    }

    return where;
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected override withTransaction(tx: PrismaClient): BaseRepository<Session, string> {
    return new PrismaSessionRepository(tx);
  }
}

// Export a singleton instance
export const sessionRepository = new PrismaSessionRepository();
