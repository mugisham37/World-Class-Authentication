import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  SecurityQuestion,
  SecurityQuestionFilterOptions,
  SecurityQuestionVerificationResult,
} from '../models/security-question.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * Security question repository interface
 * Defines security question-specific operations
 */
export interface SecurityQuestionRepository extends BaseRepository<SecurityQuestion, string> {
  /**
   * Find security questions by user ID
   * @param userId The user ID
   * @returns Array of security questions
   */
  findByUserId(userId: string): Promise<SecurityQuestion[]>;

  /**
   * Verify a security question answer
   * @param id The security question ID
   * @param answerHash The hashed answer to verify
   * @returns The verification result
   */
  verifyAnswer(id: string, answerHash: string): Promise<SecurityQuestionVerificationResult>;

  /**
   * Delete security questions by user ID
   * @param userId The user ID
   * @returns Number of deleted security questions
   */
  deleteByUserId(userId: string): Promise<number>;

  /**
   * Count security questions by user ID
   * @param userId The user ID
   * @returns Number of security questions
   */
  countByUserId(userId: string): Promise<number>;
}

/**
 * Prisma implementation of the security question repository
 */
export class PrismaSecurityQuestionRepository
  extends PrismaBaseRepository<SecurityQuestion, string>
  implements SecurityQuestionRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'securityQuestion';

  /**
   * Find security questions by user ID
   * @param userId The user ID
   * @returns Array of security questions
   */
  async findByUserId(userId: string): Promise<SecurityQuestion[]> {
    try {
      const questions = await this.prisma.securityQuestion.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
      });
      return questions;
    } catch (error) {
      logger.error('Error finding security questions by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding security questions by user ID',
        'SECURITY_QUESTION_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Verify a security question answer
   * @param id The security question ID
   * @param answerHash The hashed answer to verify
   * @returns The verification result
   */
  async verifyAnswer(id: string, answerHash: string): Promise<SecurityQuestionVerificationResult> {
    try {
      const question = await this.prisma.securityQuestion.findUnique({
        where: { id },
      });

      if (!question) {
        return {
          success: false,
          message: 'Security question not found',
        };
      }

      const isCorrect = question.answerHash === answerHash;

      return {
        success: isCorrect,
        message: isCorrect ? 'Answer is correct' : 'Answer is incorrect',
      };
    } catch (error) {
      logger.error('Error verifying security question answer', { id, error });
      throw new DatabaseError(
        'Error verifying security question answer',
        'SECURITY_QUESTION_VERIFY_ANSWER_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete security questions by user ID
   * @param userId The user ID
   * @returns Number of deleted security questions
   */
  async deleteByUserId(userId: string): Promise<number> {
    try {
      const result = await this.prisma.securityQuestion.deleteMany({
        where: { userId },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting security questions by user ID', { userId, error });
      throw new DatabaseError(
        'Error deleting security questions by user ID',
        'SECURITY_QUESTION_DELETE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count security questions by user ID
   * @param userId The user ID
   * @returns Number of security questions
   */
  async countByUserId(userId: string): Promise<number> {
    try {
      const count = await this.prisma.securityQuestion.count({
        where: { userId },
      });
      return count;
    } catch (error) {
      logger.error('Error counting security questions by user ID', { userId, error });
      throw new DatabaseError(
        'Error counting security questions by user ID',
        'SECURITY_QUESTION_COUNT_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  protected override toWhereClause(filter?: SecurityQuestionFilterOptions): any {
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

    return where;
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected override withTransaction(tx: PrismaClient): BaseRepository<SecurityQuestion, string> {
    return new PrismaSecurityQuestionRepository(tx);
  }
}

// Export a singleton instance
export const securityQuestionRepository = new PrismaSecurityQuestionRepository();
