import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  Session,
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
   * @param token Session token
   * @returns Session or null if not found
   */
  findByToken(token: string): Promise<Session | null>;

  /**
   * Find a session by refresh token
   * @param refreshToken Refresh token
   * @returns Session or null if not found
   */
  findByRefreshToken(refreshToken: string): Promise<Session | null>;

  /**
   * Find sessions by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns List of sessions
   */
  findByUserId(userId: string, options?: SessionFilterOptions): Promise<Session[]>;

  /**
   * Find active sessions by user ID
   * @param userId User ID
   * @returns List of active sessions
   */
  findActiveByUserId(userId: string): Promise<Session[]>;

  /**
   * Update a session by token
   * @param token Session token
   * @param data Session data to update
   * @returns Updated session
   */
  updateByToken(token: string, data: UpdateSessionData): Promise<Session>;

  /**
   * Delete a session by token
   * @param token Session token
   * @returns True if the session was deleted, false otherwise
   */
  deleteByToken(token: string): Promise<boolean>;

  /**
   * Delete sessions by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns Number of deleted sessions
   */
  deleteByUserId(userId: string, options?: SessionFilterOptions): Promise<number>;

  /**
   * Delete expired sessions
   * @returns Number of deleted sessions
   */
  deleteExpired(): Promise<number>;

  /**
   * Revoke a session
   * @param id Session ID
   * @param reason Revocation reason
   * @returns Updated session
   */
  revoke(id: string, reason?: string): Promise<Session>;

  /**
   * Revoke a session by token
   * @param token Session token
   * @param reason Revocation reason
   * @returns Updated session
   */
  revokeByToken(token: string, reason?: string): Promise<Session>;

  /**
   * Revoke all sessions for a user
   * @param userId User ID
   * @param reason Revocation reason
   * @param excludeSessionId Session ID to exclude from revocation
   * @returns Number of revoked sessions
   */
  revokeAllForUser(userId: string, reason?: string, excludeSessionId?: string): Promise<number>;

  /**
   * Update last active time for a session
   * @param id Session ID
   * @returns Updated session
   */
  updateLastActive(id: string): Promise<Session>;

  /**
   * Update last active time for a session by token
   * @param token Session token
   * @returns Updated session
   */
  updateLastActiveByToken(token: string): Promise<Session>;

  /**
   * Count active sessions for a user
   * @param userId User ID
   * @returns Number of active sessions
   */
  countActiveByUserId(userId: string): Promise<number>;
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
   * Find a session by ID
   * @param id Session ID
   * @returns Session or null if not found
   */
  override async findById(id: string): Promise<Session | null> {
    try {
      const session = await this.prisma.session.findUnique({
        where: { id },
      });
      return this.transformSession(session);
    } catch (error) {
      logger.error('Error finding session by ID', { id, error });
      throw new DatabaseError(
        'Error finding session by ID',
        'SESSION_FIND_BY_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find all sessions
   * @returns List of sessions
   */
  override async findAll(): Promise<Session[]> {
    try {
      const sessions = await this.prisma.session.findMany();
      return this.transformSessions(sessions);
    } catch (error) {
      logger.error('Error finding all sessions', { error });
      throw new DatabaseError(
        'Error finding all sessions',
        'SESSION_FIND_ALL_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Transform a Prisma session to a Session model
   * @param session Prisma session
   * @returns Session model or null
   */
  private transformSession(session: any): Session | null {
    if (!session) return null;
    return {
      ...session,
      isRevoked: session.revokedAt !== null
    };
  }

  /**
   * Transform an array of Prisma sessions to Session models
   * @param sessions Array of Prisma sessions
   * @returns Array of Session models
   */
  private transformSessions(sessions: any[]): Session[] {
    return sessions.map(session => ({
      ...session,
      isRevoked: session.revokedAt !== null
    }));
  }

  /**
   * Find a session by token
   * @param token Session token
   * @returns Session or null if not found
   */
  async findByToken(token: string): Promise<Session | null> {
    try {
      const session = await this.prisma.session.findUnique({
        where: { token },
      });
      return this.transformSession(session);
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
   * @param refreshToken Refresh token
   * @returns Session or null if not found
   */
  async findByRefreshToken(refreshToken: string): Promise<Session | null> {
    try {
      const session = await this.prisma.session.findUnique({
        where: { refreshToken },
      });
      return this.transformSession(session);
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
   * @param userId User ID
   * @param options Filter options
   * @returns List of sessions
   */
  async findByUserId(userId: string, options?: SessionFilterOptions): Promise<Session[]> {
    try {
      const where = this.buildWhereClause({ ...options, userId });
      const sessions = await this.prisma.session.findMany({
        where,
        orderBy: { lastActiveAt: 'desc' },
      });
      return this.transformSessions(sessions);
    } catch (error) {
      logger.error('Error finding sessions by user ID', { userId, options, error });
      throw new DatabaseError(
        'Error finding sessions by user ID',
        'SESSION_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find active sessions by user ID
   * @param userId User ID
   * @returns List of active sessions
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
      return this.transformSessions(sessions);
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
   * Update a session by token
   * @param token Session token
   * @param data Session data to update
   * @returns Updated session
   */
  async updateByToken(token: string, data: UpdateSessionData): Promise<Session> {
    try {
      const session = await this.prisma.session.update({
        where: { token },
        data,
      });
      return this.transformSession(session)!;
    } catch (error) {
      logger.error('Error updating session by token', { token, error });
      throw new DatabaseError(
        'Error updating session by token',
        'SESSION_UPDATE_BY_TOKEN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete a session by token
   * @param token Session token
   * @returns True if the session was deleted, false otherwise
   */
  async deleteByToken(token: string): Promise<boolean> {
    try {
      await this.prisma.session.delete({
        where: { token },
      });
      return true;
    } catch (error) {
      logger.error('Error deleting session by token', { token, error });

      // Check if the error is a record not found error
      if (error instanceof Error && error.message.includes('Record to delete does not exist')) {
        return false;
      }

      throw new DatabaseError(
        'Error deleting session by token',
        'SESSION_DELETE_BY_TOKEN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete sessions by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns Number of deleted sessions
   */
  async deleteByUserId(userId: string, options?: SessionFilterOptions): Promise<number> {
    try {
      const where = this.buildWhereClause({ ...options, userId });
      const result = await this.prisma.session.deleteMany({
        where,
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting sessions by user ID', { userId, options, error });
      throw new DatabaseError(
        'Error deleting sessions by user ID',
        'SESSION_DELETE_BY_USER_ID_ERROR',
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
   * Revoke a session
   * @param id Session ID
   * @param reason Revocation reason
   * @returns Updated session
   */
  async revoke(id: string, reason?: string): Promise<Session> {
    try {
      const session = await this.prisma.session.update({
        where: { id },
        data: {
          revokedAt: new Date(),
          revocationReason: reason || 'Manually revoked',
        },
      });
      return this.transformSession(session)!;
    } catch (error) {
      logger.error('Error revoking session', { id, reason, error });
      throw new DatabaseError(
        'Error revoking session',
        'SESSION_REVOKE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Revoke a session by token
   * @param token Session token
   * @param reason Revocation reason
   * @returns Updated session
   */
  async revokeByToken(token: string, reason?: string): Promise<Session> {
    try {
      const session = await this.prisma.session.update({
        where: { token },
        data: {
          revokedAt: new Date(),
          revocationReason: reason || 'Manually revoked',
        },
      });
      return this.transformSession(session)!;
    } catch (error) {
      logger.error('Error revoking session by token', { token, reason, error });
      throw new DatabaseError(
        'Error revoking session by token',
        'SESSION_REVOKE_BY_TOKEN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Revoke all sessions for a user
   * @param userId User ID
   * @param reason Revocation reason
   * @param excludeSessionId Session ID to exclude from revocation
   * @returns Number of revoked sessions
   */
  async revokeAllForUser(
    userId: string,
    reason?: string,
    excludeSessionId?: string
  ): Promise<number> {
    try {
      const where: any = {
        userId,
        revokedAt: null,
      };

      if (excludeSessionId) {
        where.id = { not: excludeSessionId };
      }

      const result = await this.prisma.session.updateMany({
        where,
        data: {
          revokedAt: new Date(),
          revocationReason: reason || 'Revoked as part of user-wide revocation',
        },
      });

      return result.count;
    } catch (error) {
      logger.error('Error revoking all sessions for user', {
        userId,
        reason,
        excludeSessionId,
        error,
      });
      throw new DatabaseError(
        'Error revoking all sessions for user',
        'SESSION_REVOKE_ALL_FOR_USER_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update last active time for a session
   * @param id Session ID
   * @returns Updated session
   */
  async updateLastActive(id: string): Promise<Session> {
    try {
      const session = await this.prisma.session.update({
        where: { id },
        data: {
          lastActiveAt: new Date(),
        },
      });
      return this.transformSession(session)!;
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
   * Update last active time for a session by token
   * @param token Session token
   * @returns Updated session
   */
  async updateLastActiveByToken(token: string): Promise<Session> {
    try {
      const session = await this.prisma.session.update({
        where: { token },
        data: {
          lastActiveAt: new Date(),
        },
      });
      return this.transformSession(session)!;
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
   * Count active sessions for a user
   * @param userId User ID
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
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  private buildWhereClause(filter?: SessionFilterOptions): any {
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

    // Boolean filters
    if (filter.isActive !== undefined) {
      const now = new Date();
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
  /**
   * Create a new session
   * @param data Session data
   * @returns Created session
   */
  override async create(data: any): Promise<Session> {
    try {
      const session = await this.prisma.session.create({
        data,
      });
      return this.transformSession(session)!;
    } catch (error) {
      logger.error('Error creating session', { error });
      throw new DatabaseError(
        'Error creating session',
        'SESSION_CREATE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update a session
   * @param id Session ID
   * @param data Session data
   * @returns Updated session
   */
  override async update(id: string, data: any): Promise<Session> {
    try {
      const session = await this.prisma.session.update({
        where: { id },
        data,
      });
      return this.transformSession(session)!;
    } catch (error) {
      logger.error('Error updating session', { id, error });
      throw new DatabaseError(
        'Error updating session',
        'SESSION_UPDATE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  protected withTransaction(tx: PrismaClient): BaseRepository<Session, string> {
    return new PrismaSessionRepository(tx);
  }
}

// Export a singleton instance
export const sessionRepository = new PrismaSessionRepository();
