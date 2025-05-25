import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  MfaChallenge,
  MfaChallengeStatus,
  CreateMfaChallengeData,
  UpdateMfaChallengeData,
  MfaChallengeFilterOptions,
  MfaChallengeVerificationResult,
} from '../models/mfa-challenge.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';
import { prisma } from '../prisma/client';

/**
 * MFA challenge repository interface
 * Defines MFA challenge-specific operations
 */
export interface MfaChallengeRepository extends BaseRepository<MfaChallenge, string> {
  /**
   * Find MFA challenges by factor ID
   * @param factorId Factor ID
   * @param options Filter options
   * @returns List of MFA challenges
   */
  findByFactorId(factorId: string, options?: MfaChallengeFilterOptions): Promise<MfaChallenge[]>;

  /**
   * Find active MFA challenges by factor ID
   * @param factorId Factor ID
   * @returns List of active MFA challenges
   */
  findActiveByFactorId(factorId: string): Promise<MfaChallenge[]>;

  /**
   * Find an MFA challenge by challenge string
   * @param challenge Challenge string
   * @returns MFA challenge or null if not found
   */
  findByChallenge(challenge: string): Promise<MfaChallenge | null>;

  /**
   * Update an MFA challenge's status
   * @param id MFA challenge ID
   * @param status New status
   * @returns Updated MFA challenge
   */
  updateStatus(id: string, status: MfaChallengeStatus): Promise<MfaChallenge>;

  /**
   * Mark an MFA challenge as completed
   * @param id MFA challenge ID
   * @param response Challenge response
   * @returns Updated MFA challenge
   */
  markAsCompleted(id: string, response?: string): Promise<MfaChallenge>;

  /**
   * Mark an MFA challenge as failed
   * @param id MFA challenge ID
   * @returns Updated MFA challenge
   */
  markAsFailed(id: string): Promise<MfaChallenge>;

  /**
   * Mark an MFA challenge as expired
   * @param id MFA challenge ID
   * @returns Updated MFA challenge
   */
  markAsExpired(id: string): Promise<MfaChallenge>;

  /**
   * Increment the attempts counter for an MFA challenge
   * @param id MFA challenge ID
   * @returns Updated MFA challenge
   */
  incrementAttempts(id: string): Promise<MfaChallenge>;

  /**
   * Verify an MFA challenge response
   * @param id MFA challenge ID
   * @param response Challenge response
   * @returns Verification result
   */
  verifyChallenge(id: string, response: string): Promise<MfaChallengeVerificationResult>;

  /**
   * Delete expired MFA challenges
   * @returns Number of deleted challenges
   */
  deleteExpired(): Promise<number>;

  /**
   * Delete MFA challenges by factor ID
   * @param factorId Factor ID
   * @param options Filter options
   * @returns Number of deleted challenges
   */
  deleteByFactorId(factorId: string, options?: MfaChallengeFilterOptions): Promise<number>;
}

/**
 * Prisma implementation of the MFA challenge repository
 */
export class PrismaMfaChallengeRepository
  extends PrismaBaseRepository<MfaChallenge, string>
  implements MfaChallengeRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'mfaChallenge';

  /**
   * Find MFA challenges by factor ID
   * @param factorId Factor ID
   * @param options Filter options
   * @returns List of MFA challenges
   */
  async findByFactorId(
    factorId: string,
    options?: MfaChallengeFilterOptions
  ): Promise<MfaChallenge[]> {
    try {
      const where = this.buildWhereClause({ ...options, factorId });
      const challenges = await this.prisma.mfaChallenge.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return challenges;
    } catch (error) {
      logger.error('Error finding MFA challenges by factor ID', { factorId, options, error });
      throw new DatabaseError(
        'Error finding MFA challenges by factor ID',
        'MFA_CHALLENGE_FIND_BY_FACTOR_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find active MFA challenges by factor ID
   * @param factorId Factor ID
   * @returns List of active MFA challenges
   */
  async findActiveByFactorId(factorId: string): Promise<MfaChallenge[]> {
    try {
      const now = new Date();
      const challenges = await this.prisma.mfaChallenge.findMany({
        where: {
          factorId,
          status: MfaChallengeStatus.PENDING,
          expiresAt: { gt: now },
        },
        orderBy: { createdAt: 'desc' },
      });
      return challenges;
    } catch (error) {
      logger.error('Error finding active MFA challenges by factor ID', { factorId, error });
      throw new DatabaseError(
        'Error finding active MFA challenges by factor ID',
        'MFA_CHALLENGE_FIND_ACTIVE_BY_FACTOR_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find an MFA challenge by challenge string
   * @param challenge Challenge string
   * @returns MFA challenge or null if not found
   */
  async findByChallenge(challenge: string): Promise<MfaChallenge | null> {
    try {
      const mfaChallenge = await this.prisma.mfaChallenge.findFirst({
        where: { challenge },
      });
      return mfaChallenge;
    } catch (error) {
      logger.error('Error finding MFA challenge by challenge string', { challenge, error });
      throw new DatabaseError(
        'Error finding MFA challenge by challenge string',
        'MFA_CHALLENGE_FIND_BY_CHALLENGE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update an MFA challenge's status
   * @param id MFA challenge ID
   * @param status New status
   * @returns Updated MFA challenge
   */
  async updateStatus(id: string, status: MfaChallengeStatus): Promise<MfaChallenge> {
    try {
      const challenge = await this.prisma.mfaChallenge.update({
        where: { id },
        data: { status },
      });
      return challenge;
    } catch (error) {
      logger.error('Error updating MFA challenge status', { id, status, error });
      throw new DatabaseError(
        'Error updating MFA challenge status',
        'MFA_CHALLENGE_UPDATE_STATUS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Mark an MFA challenge as completed
   * @param id MFA challenge ID
   * @param response Challenge response
   * @returns Updated MFA challenge
   */
  async markAsCompleted(id: string, response?: string): Promise<MfaChallenge> {
    try {
      const challenge = await this.prisma.mfaChallenge.update({
        where: { id },
        data: {
          status: MfaChallengeStatus.COMPLETED,
          completedAt: new Date(),
          response,
        },
      });
      return challenge;
    } catch (error) {
      logger.error('Error marking MFA challenge as completed', { id, error });
      throw new DatabaseError(
        'Error marking MFA challenge as completed',
        'MFA_CHALLENGE_MARK_AS_COMPLETED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Mark an MFA challenge as failed
   * @param id MFA challenge ID
   * @returns Updated MFA challenge
   */
  async markAsFailed(id: string): Promise<MfaChallenge> {
    try {
      const challenge = await this.prisma.mfaChallenge.update({
        where: { id },
        data: {
          status: MfaChallengeStatus.FAILED,
          completedAt: new Date(),
        },
      });
      return challenge;
    } catch (error) {
      logger.error('Error marking MFA challenge as failed', { id, error });
      throw new DatabaseError(
        'Error marking MFA challenge as failed',
        'MFA_CHALLENGE_MARK_AS_FAILED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Mark an MFA challenge as expired
   * @param id MFA challenge ID
   * @returns Updated MFA challenge
   */
  async markAsExpired(id: string): Promise<MfaChallenge> {
    try {
      const challenge = await this.prisma.mfaChallenge.update({
        where: { id },
        data: {
          status: MfaChallengeStatus.EXPIRED,
        },
      });
      return challenge;
    } catch (error) {
      logger.error('Error marking MFA challenge as expired', { id, error });
      throw new DatabaseError(
        'Error marking MFA challenge as expired',
        'MFA_CHALLENGE_MARK_AS_EXPIRED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Increment the attempts counter for an MFA challenge
   * @param id MFA challenge ID
   * @returns Updated MFA challenge
   */
  async incrementAttempts(id: string): Promise<MfaChallenge> {
    try {
      const challenge = await this.prisma.mfaChallenge.update({
        where: { id },
        data: {
          attempts: {
            increment: 1,
          },
        },
      });
      return challenge;
    } catch (error) {
      logger.error('Error incrementing MFA challenge attempts', { id, error });
      throw new DatabaseError(
        'Error incrementing MFA challenge attempts',
        'MFA_CHALLENGE_INCREMENT_ATTEMPTS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Verify an MFA challenge response
   * @param id MFA challenge ID
   * @param response Challenge response
   * @returns Verification result
   */
  async verifyChallenge(id: string, response: string): Promise<MfaChallengeVerificationResult> {
    try {
      // Get the challenge
      const challenge = await this.prisma.mfaChallenge.findUnique({
        where: { id },
      });

      if (!challenge) {
        return {
          success: false,
          challenge: null as any, // This will be handled by the caller
          message: 'Challenge not found',
        };
      }

      // Check if the challenge is still valid
      const now = new Date();
      if (challenge.expiresAt < now) {
        // Mark as expired and return failure
        const updatedChallenge = await this.markAsExpired(id);
        return {
          success: false,
          challenge: updatedChallenge,
          message: 'Challenge has expired',
        };
      }

      // Check if the challenge is already completed, failed, or expired
      if (challenge.status !== MfaChallengeStatus.PENDING) {
        return {
          success: false,
          challenge,
          message: `Challenge is ${challenge.status.toLowerCase()}`,
        };
      }

      // Increment the attempts counter
      const updatedChallenge = await this.incrementAttempts(id);

      // Verify the response (this is a simplified check - in a real system,
      // you would likely have more complex verification logic based on the factor type)
      if (response === challenge.challenge) {
        // Mark as completed and return success
        const completedChallenge = await this.markAsCompleted(id, response);
        return {
          success: true,
          challenge: completedChallenge,
          message: 'Challenge verified successfully',
        };
      } else {
        // If max attempts reached, mark as failed
        if (updatedChallenge.attempts >= 3) {
          const failedChallenge = await this.markAsFailed(id);
          return {
            success: false,
            challenge: failedChallenge,
            message: 'Maximum attempts reached',
          };
        }

        // Otherwise, return failure but keep the challenge pending
        return {
          success: false,
          challenge: updatedChallenge,
          message: 'Invalid response',
        };
      }
    } catch (error) {
      logger.error('Error verifying MFA challenge', { id, error });
      throw new DatabaseError(
        'Error verifying MFA challenge',
        'MFA_CHALLENGE_VERIFY_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete expired MFA challenges
   * @returns Number of deleted challenges
   */
  async deleteExpired(): Promise<number> {
    try {
      const now = new Date();
      const result = await this.prisma.mfaChallenge.deleteMany({
        where: {
          expiresAt: { lt: now },
          status: MfaChallengeStatus.PENDING,
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting expired MFA challenges', { error });
      throw new DatabaseError(
        'Error deleting expired MFA challenges',
        'MFA_CHALLENGE_DELETE_EXPIRED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete MFA challenges by factor ID
   * @param factorId Factor ID
   * @param options Filter options
   * @returns Number of deleted challenges
   */
  async deleteByFactorId(factorId: string, options?: MfaChallengeFilterOptions): Promise<number> {
    try {
      const where = this.buildWhereClause({ ...options, factorId });
      const result = await this.prisma.mfaChallenge.deleteMany({
        where,
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting MFA challenges by factor ID', { factorId, options, error });
      throw new DatabaseError(
        'Error deleting MFA challenges by factor ID',
        'MFA_CHALLENGE_DELETE_BY_FACTOR_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  private buildWhereClause(filter?: MfaChallengeFilterOptions): any {
    if (!filter) {
      return {};
    }

    const where: any = {};

    if (filter.id) {
      where.id = filter.id;
    }

    if (filter.factorId) {
      where.factorId = filter.factorId;
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

    if (filter.expiresAtBefore || filter.expiresAtAfter) {
      where.expiresAt = {};

      if (filter.expiresAtBefore) {
        where.expiresAt.lte = filter.expiresAtBefore;
      }

      if (filter.expiresAtAfter) {
        where.expiresAt.gte = filter.expiresAtAfter;
      }
    }

    if (filter.completedAtBefore || filter.completedAtAfter) {
      where.completedAt = {};

      if (filter.completedAtBefore) {
        where.completedAt.lte = filter.completedAtBefore;
      }

      if (filter.completedAtAfter) {
        where.completedAt.gte = filter.completedAtAfter;
      }
    }

    return where;
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected withTransaction(tx: PrismaClient): BaseRepository<MfaChallenge, string> {
    return new PrismaMfaChallengeRepository(tx);
  }
}

// Export a singleton instance
export const mfaChallengeRepository = new PrismaMfaChallengeRepository();
