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

/**
 * MFA challenge repository interface
 * Defines MFA challenge-specific operations
 */
export interface MfaChallengeRepository extends BaseRepository<MfaChallenge, string> {
  /**
   * Find MFA challenges by factor ID
   * @param factorId The MFA factor ID
   * @returns Array of MFA challenges
   */
  findByFactorId(factorId: string): Promise<MfaChallenge[]>;

  /**
   * Find active MFA challenges by factor ID
   * @param factorId The MFA factor ID
   * @returns Array of active MFA challenges
   */
  findActiveByFactorId(factorId: string): Promise<MfaChallenge[]>;

  /**
   * Find the latest MFA challenge by factor ID
   * @param factorId The MFA factor ID
   * @returns The latest MFA challenge or null if not found
   */
  findLatestByFactorId(factorId: string): Promise<MfaChallenge | null>;

  /**
   * Verify an MFA challenge
   * @param id The MFA challenge ID
   * @param response The response to verify
   * @returns The verification result
   */
  verifyChallenge(id: string, response: string): Promise<MfaChallengeVerificationResult>;

  /**
   * Increment the attempts count for an MFA challenge
   * @param id The MFA challenge ID
   * @returns The updated MFA challenge
   */
  incrementAttempts(id: string): Promise<MfaChallenge>;

  /**
   * Complete an MFA challenge
   * @param id The MFA challenge ID
   * @param success Whether the challenge was successful
   * @returns The updated MFA challenge
   */
  completeChallenge(id: string, success: boolean): Promise<MfaChallenge>;

  /**
   * Expire MFA challenges
   * @returns Number of expired MFA challenges
   */
  expireOldChallenges(): Promise<number>;

  /**
   * Delete MFA challenges by factor ID
   * @param factorId The MFA factor ID
   * @returns Number of deleted MFA challenges
   */
  deleteByFactorId(factorId: string): Promise<number>;
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
   * @param factorId The MFA factor ID
   * @returns Array of MFA challenges
   */
  async findByFactorId(factorId: string): Promise<MfaChallenge[]> {
    try {
      const challenges = await this.prisma.mfaChallenge.findMany({
        where: { factorId },
        orderBy: { createdAt: 'desc' },
      });
      return challenges;
    } catch (error) {
      logger.error('Error finding MFA challenges by factor ID', { factorId, error });
      throw new DatabaseError(
        'Error finding MFA challenges by factor ID',
        'MFA_CHALLENGE_FIND_BY_FACTOR_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find active MFA challenges by factor ID
   * @param factorId The MFA factor ID
   * @returns Array of active MFA challenges
   */
  async findActiveByFactorId(factorId: string): Promise<MfaChallenge[]> {
    try {
      const now = new Date();
      const challenges = await this.prisma.mfaChallenge.findMany({
        where: {
          factorId,
          status: MfaChallengeStatus.PENDING,
          expiresAt: {
            gt: now,
          },
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
   * Find the latest MFA challenge by factor ID
   * @param factorId The MFA factor ID
   * @returns The latest MFA challenge or null if not found
   */
  async findLatestByFactorId(factorId: string): Promise<MfaChallenge | null> {
    try {
      const challenge = await this.prisma.mfaChallenge.findFirst({
        where: { factorId },
        orderBy: { createdAt: 'desc' },
      });
      return challenge;
    } catch (error) {
      logger.error('Error finding latest MFA challenge by factor ID', { factorId, error });
      throw new DatabaseError(
        'Error finding latest MFA challenge by factor ID',
        'MFA_CHALLENGE_FIND_LATEST_BY_FACTOR_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Verify an MFA challenge
   * @param id The MFA challenge ID
   * @param response The response to verify
   * @returns The verification result
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
          challenge: null as unknown as MfaChallenge,
          message: 'Challenge not found',
        };
      }

      // Check if the challenge is expired
      const now = new Date();
      if (challenge.expiresAt < now) {
        // Update the challenge status to expired
        const updatedChallenge = await this.prisma.mfaChallenge.update({
          where: { id },
          data: {
            status: MfaChallengeStatus.EXPIRED,
          },
        });

        return {
          success: false,
          challenge: updatedChallenge,
          message: 'Challenge expired',
        };
      }

      // Check if the challenge is already completed or failed
      if (challenge.status !== MfaChallengeStatus.PENDING) {
        return {
          success: false,
          challenge,
          message: `Challenge is ${challenge.status.toLowerCase()}`,
        };
      }

      // Increment attempts
      const updatedChallenge = await this.incrementAttempts(id);

      // Check if the response matches
      if (response === challenge.challenge) {
        // Complete the challenge successfully
        const completedChallenge = await this.completeChallenge(id, true);

        return {
          success: true,
          challenge: completedChallenge,
          message: 'Challenge verified successfully',
        };
      } else {
        // Check if max attempts reached
        if (updatedChallenge.attempts >= 3) {
          // Complete the challenge with failure
          const failedChallenge = await this.completeChallenge(id, false);

          return {
            success: false,
            challenge: failedChallenge,
            message: 'Maximum attempts reached',
          };
        }

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
   * Increment the attempts count for an MFA challenge
   * @param id The MFA challenge ID
   * @returns The updated MFA challenge
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
   * Complete an MFA challenge
   * @param id The MFA challenge ID
   * @param success Whether the challenge was successful
   * @returns The updated MFA challenge
   */
  async completeChallenge(id: string, success: boolean): Promise<MfaChallenge> {
    try {
      const now = new Date();
      const challenge = await this.prisma.mfaChallenge.update({
        where: { id },
        data: {
          status: success ? MfaChallengeStatus.COMPLETED : MfaChallengeStatus.FAILED,
          completedAt: now,
        },
      });
      return challenge;
    } catch (error) {
      logger.error('Error completing MFA challenge', { id, error });
      throw new DatabaseError(
        'Error completing MFA challenge',
        'MFA_CHALLENGE_COMPLETE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Expire MFA challenges
   * @returns Number of expired MFA challenges
   */
  async expireOldChallenges(): Promise<number> {
    try {
      const now = new Date();
      const result = await this.prisma.mfaChallenge.updateMany({
        where: {
          status: MfaChallengeStatus.PENDING,
          expiresAt: {
            lt: now,
          },
        },
        data: {
          status: MfaChallengeStatus.EXPIRED,
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error expiring old MFA challenges', { error });
      throw new DatabaseError(
        'Error expiring old MFA challenges',
        'MFA_CHALLENGE_EXPIRE_OLD_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete MFA challenges by factor ID
   * @param factorId The MFA factor ID
   * @returns Number of deleted MFA challenges
   */
  async deleteByFactorId(factorId: string): Promise<number> {
    try {
      const result = await this.prisma.mfaChallenge.deleteMany({
        where: { factorId },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting MFA challenges by factor ID', { factorId, error });
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
  protected override toWhereClause(filter?: MfaChallengeFilterOptions): any {
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
  protected override withTransaction(tx: PrismaClient): BaseRepository<MfaChallenge, string> {
    return new PrismaMfaChallengeRepository(tx);
  }
}

// Export a singleton instance
export const mfaChallengeRepository = new PrismaMfaChallengeRepository();
