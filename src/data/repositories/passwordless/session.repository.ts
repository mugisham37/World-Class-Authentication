import { Injectable } from '@tsed/di';
import { v4 as uuidv4 } from 'uuid';
import { PrismaClient } from '@prisma/client';
import { logger } from '../../../infrastructure/logging/logger';
import {
  PasswordlessSession,
  CreatePasswordlessSessionData,
  UpdatePasswordlessSessionData,
  PasswordlessSessionQueryOptions,
} from '../../models/passwordless-session.model';
import { PasswordlessSessionError } from '../../../utils/errors/passwordless-session.error';

/**
 * Repository for passwordless authentication sessions
 */
@Injectable()
export class PasswordlessSessionRepository {
  constructor(private prisma: PrismaClient) {}

  /**
   * Create a new passwordless session
   * @param data Session data
   * @returns Created session
   */
  async create(data: CreatePasswordlessSessionData): Promise<PasswordlessSession> {
    try {
      return await this.prisma.passwordlessSession.create({
        data: {
          id: data.id || uuidv4(),
          userId: data.userId,
          method: data.method,
          identifier: data.identifier,
          challengeId: data.challengeId,
          expiresAt: data.expiresAt,
          isRegistration: data.isRegistration || false,
          completedAt: data.completedAt || null,
          createdAt: new Date(),
          metadata: data.metadata || {},
        },
      });
    } catch (error) {
      logger.error('Failed to create passwordless session', { error, data });
      throw new PasswordlessSessionError(
        'Failed to create passwordless session',
        'SESSION_CREATE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find a passwordless session by ID
   * @param id Session ID
   * @returns Session or null if not found
   */
  async findById(id: string): Promise<PasswordlessSession | null> {
    try {
      return await this.prisma.passwordlessSession.findUnique({
        where: { id },
      });
    } catch (error) {
      logger.error('Failed to find passwordless session by ID', { error, id });
      throw new PasswordlessSessionError(
        'Failed to find passwordless session by ID',
        'SESSION_FIND_BY_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find passwordless sessions by user ID
   * @param userId User ID
   * @param options Query options
   * @returns List of sessions
   */
  async findByUserId(
    userId: string,
    options: PasswordlessSessionQueryOptions = {}
  ): Promise<PasswordlessSession[]> {
    try {
      const where: any = { userId };

      if (options.method) {
        where.method = options.method;
      }

      if (options.isRegistration !== undefined) {
        where.isRegistration = options.isRegistration;
      }

      if (options.isCompleted !== undefined) {
        where.completedAt = options.isCompleted ? { not: null } : null;
      }

      return await this.prisma.passwordlessSession.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        ...(options.limit ? { take: options.limit } : {}),
      });
    } catch (error) {
      logger.error('Failed to find passwordless sessions by user ID', { error, userId, options });
      throw new PasswordlessSessionError(
        'Failed to find passwordless sessions by user ID',
        'SESSION_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find active passwordless sessions by user ID
   * @param userId User ID
   * @param options Query options
   * @returns List of active sessions
   */
  async findActiveByUserId(
    userId: string,
    options: Omit<PasswordlessSessionQueryOptions, 'isCompleted'> = {}
  ): Promise<PasswordlessSession[]> {
    try {
      const now = new Date();
      const where: any = {
        userId,
        expiresAt: { gt: now },
        completedAt: null,
      };

      if (options.method) {
        where.method = options.method;
      }

      if (options.isRegistration !== undefined) {
        where.isRegistration = options.isRegistration;
      }

      return await this.prisma.passwordlessSession.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        ...(options.limit ? { take: options.limit } : {}),
      });
    } catch (error) {
      logger.error('Failed to find active passwordless sessions by user ID', {
        error,
        userId,
        options,
      });
      throw new PasswordlessSessionError(
        'Failed to find active passwordless sessions by user ID',
        'SESSION_FIND_ACTIVE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find a passwordless session by challenge ID
   * @param challengeId Challenge ID
   * @returns Session or null if not found
   */
  async findByChallengeId(challengeId: string): Promise<PasswordlessSession | null> {
    try {
      return await this.prisma.passwordlessSession.findFirst({
        where: { challengeId },
      });
    } catch (error) {
      logger.error('Failed to find passwordless session by challenge ID', { error, challengeId });
      throw new PasswordlessSessionError(
        'Failed to find passwordless session by challenge ID',
        'SESSION_FIND_BY_CHALLENGE_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update a passwordless session
   * @param id Session ID
   * @param data Update data
   * @returns Updated session
   */
  async update(id: string, data: UpdatePasswordlessSessionData): Promise<PasswordlessSession> {
    try {
      return await this.prisma.passwordlessSession.update({
        where: { id },
        data: {
          ...data,
          updatedAt: new Date(),
        },
      });
    } catch (error) {
      logger.error('Failed to update passwordless session', { error, id, data });
      throw new PasswordlessSessionError(
        'Failed to update passwordless session',
        'SESSION_UPDATE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete a passwordless session
   * @param id Session ID
   * @returns True if deleted, false otherwise
   */
  async delete(id: string): Promise<boolean> {
    try {
      await this.prisma.passwordlessSession.delete({
        where: { id },
      });
      return true;
    } catch (error) {
      logger.error('Failed to delete passwordless session', { error, id });
      if (error instanceof Error && error.message.includes('Record to delete does not exist')) {
        return false;
      }
      throw new PasswordlessSessionError(
        'Failed to delete passwordless session',
        'SESSION_DELETE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete expired passwordless sessions
   * @returns Number of deleted sessions
   */
  async deleteExpired(): Promise<number> {
    try {
      const now = new Date();
      const result = await this.prisma.passwordlessSession.deleteMany({
        where: {
          expiresAt: { lt: now },
          completedAt: null,
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Failed to delete expired passwordless sessions', { error });
      throw new PasswordlessSessionError(
        'Failed to delete expired passwordless sessions',
        'SESSION_DELETE_EXPIRED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count passwordless sessions by method
   * @param options Query options
   * @returns Count by method
   */
  async countByMethod(
    options: {
      userId?: string;
      startDate?: Date;
      endDate?: Date;
      isRegistration?: boolean;
      isCompleted?: boolean;
    } = {}
  ): Promise<Record<string, number>> {
    try {
      const where: any = {};

      if (options.userId) {
        where.userId = options.userId;
      }

      if (options.startDate || options.endDate) {
        where.createdAt = {};
        if (options.startDate) {
          where.createdAt.gte = options.startDate;
        }
        if (options.endDate) {
          where.createdAt.lte = options.endDate;
        }
      }

      if (options.isRegistration !== undefined) {
        where.isRegistration = options.isRegistration;
      }

      if (options.isCompleted !== undefined) {
        where.completedAt = options.isCompleted ? { not: null } : null;
      }

      const sessions = await this.prisma.passwordlessSession.findMany({
        where,
        select: {
          method: true,
        },
      });

      const counts: Record<string, number> = {};
      for (const session of sessions) {
        counts[session.method] = (counts[session.method] || 0) + 1;
      }

      return counts;
    } catch (error) {
      logger.error('Failed to count passwordless sessions by method', { error, options });
      throw new PasswordlessSessionError(
        'Failed to count passwordless sessions by method',
        'SESSION_COUNT_BY_METHOD_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }
}
