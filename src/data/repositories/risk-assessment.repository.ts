import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  RiskAssessment,
  RiskLevel,
  CreateRiskAssessmentData,
  UpdateRiskAssessmentData,
  RiskAssessmentFilterOptions,
} from '../models/risk-assessment.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * Risk assessment repository interface
 * Defines risk assessment-specific operations
 */
export interface RiskAssessmentRepository extends BaseRepository<RiskAssessment, string> {
  /**
   * Find risk assessments by user ID
   * @param userId The user ID
   * @returns Array of risk assessments
   */
  findByUserId(userId: string): Promise<RiskAssessment[]>;

  /**
   * Find risk assessments by session ID
   * @param sessionId The session ID
   * @returns Array of risk assessments
   */
  findBySessionId(sessionId: string): Promise<RiskAssessment[]>;

  /**
   * Find risk assessments by IP address
   * @param ipAddress The IP address
   * @returns Array of risk assessments
   */
  findByIpAddress(ipAddress: string): Promise<RiskAssessment[]>;

  /**
   * Find risk assessments by device ID
   * @param deviceId The device ID
   * @returns Array of risk assessments
   */
  findByDeviceId(deviceId: string): Promise<RiskAssessment[]>;

  /**
   * Find risk assessments by risk level
   * @param riskLevel The risk level
   * @returns Array of risk assessments
   */
  findByRiskLevel(riskLevel: RiskLevel): Promise<RiskAssessment[]>;

  /**
   * Find unresolved risk assessments
   * @returns Array of unresolved risk assessments
   */
  findUnresolved(): Promise<RiskAssessment[]>;

  /**
   * Find unresolved risk assessments by user ID
   * @param userId The user ID
   * @returns Array of unresolved risk assessments
   */
  findUnresolvedByUserId(userId: string): Promise<RiskAssessment[]>;

  /**
   * Find high risk assessments (HIGH or CRITICAL)
   * @returns Array of high risk assessments
   */
  findHighRisk(): Promise<RiskAssessment[]>;

  /**
   * Mark a risk assessment as resolved
   * @param id The risk assessment ID
   * @param resolution The resolution description
   * @returns The updated risk assessment
   */
  markAsResolved(id: string, resolution: string): Promise<RiskAssessment>;

  /**
   * Delete risk assessments by user ID
   * @param userId The user ID
   * @returns Number of deleted risk assessments
   */
  deleteByUserId(userId: string): Promise<number>;

  /**
   * Delete risk assessments by session ID
   * @param sessionId The session ID
   * @returns Number of deleted risk assessments
   */
  deleteBySessionId(sessionId: string): Promise<number>;

  /**
   * Delete resolved risk assessments older than a specified date
   * @param date The cutoff date
   * @returns Number of deleted risk assessments
   */
  deleteResolvedOlderThan(date: Date): Promise<number>;
}

/**
 * Prisma implementation of the risk assessment repository
 */
export class PrismaRiskAssessmentRepository
  extends PrismaBaseRepository<RiskAssessment, string>
  implements RiskAssessmentRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'riskAssessment';

  /**
   * Find risk assessments by user ID
   * @param userId The user ID
   * @returns Array of risk assessments
   */
  async findByUserId(userId: string): Promise<RiskAssessment[]> {
    try {
      const assessments = await this.prisma.riskAssessment.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding risk assessments by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding risk assessments by user ID',
        'RISK_ASSESSMENT_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find risk assessments by session ID
   * @param sessionId The session ID
   * @returns Array of risk assessments
   */
  async findBySessionId(sessionId: string): Promise<RiskAssessment[]> {
    try {
      const assessments = await this.prisma.riskAssessment.findMany({
        where: { sessionId },
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding risk assessments by session ID', { sessionId, error });
      throw new DatabaseError(
        'Error finding risk assessments by session ID',
        'RISK_ASSESSMENT_FIND_BY_SESSION_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find risk assessments by IP address
   * @param ipAddress The IP address
   * @returns Array of risk assessments
   */
  async findByIpAddress(ipAddress: string): Promise<RiskAssessment[]> {
    try {
      const assessments = await this.prisma.riskAssessment.findMany({
        where: { ipAddress },
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding risk assessments by IP address', { ipAddress, error });
      throw new DatabaseError(
        'Error finding risk assessments by IP address',
        'RISK_ASSESSMENT_FIND_BY_IP_ADDRESS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find risk assessments by device ID
   * @param deviceId The device ID
   * @returns Array of risk assessments
   */
  async findByDeviceId(deviceId: string): Promise<RiskAssessment[]> {
    try {
      const assessments = await this.prisma.riskAssessment.findMany({
        where: { deviceId },
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding risk assessments by device ID', { deviceId, error });
      throw new DatabaseError(
        'Error finding risk assessments by device ID',
        'RISK_ASSESSMENT_FIND_BY_DEVICE_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find risk assessments by risk level
   * @param riskLevel The risk level
   * @returns Array of risk assessments
   */
  async findByRiskLevel(riskLevel: RiskLevel): Promise<RiskAssessment[]> {
    try {
      const assessments = await this.prisma.riskAssessment.findMany({
        where: { riskLevel },
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding risk assessments by risk level', { riskLevel, error });
      throw new DatabaseError(
        'Error finding risk assessments by risk level',
        'RISK_ASSESSMENT_FIND_BY_RISK_LEVEL_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find unresolved risk assessments
   * @returns Array of unresolved risk assessments
   */
  async findUnresolved(): Promise<RiskAssessment[]> {
    try {
      const assessments = await this.prisma.riskAssessment.findMany({
        where: { resolvedAt: null },
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding unresolved risk assessments', { error });
      throw new DatabaseError(
        'Error finding unresolved risk assessments',
        'RISK_ASSESSMENT_FIND_UNRESOLVED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find unresolved risk assessments by user ID
   * @param userId The user ID
   * @returns Array of unresolved risk assessments
   */
  async findUnresolvedByUserId(userId: string): Promise<RiskAssessment[]> {
    try {
      const assessments = await this.prisma.riskAssessment.findMany({
        where: {
          userId,
          resolvedAt: null,
        },
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding unresolved risk assessments by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding unresolved risk assessments by user ID',
        'RISK_ASSESSMENT_FIND_UNRESOLVED_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find high risk assessments (HIGH or CRITICAL)
   * @returns Array of high risk assessments
   */
  async findHighRisk(): Promise<RiskAssessment[]> {
    try {
      const assessments = await this.prisma.riskAssessment.findMany({
        where: {
          riskLevel: {
            in: [RiskLevel.HIGH, RiskLevel.CRITICAL],
          },
        },
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding high risk assessments', { error });
      throw new DatabaseError(
        'Error finding high risk assessments',
        'RISK_ASSESSMENT_FIND_HIGH_RISK_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Mark a risk assessment as resolved
   * @param id The risk assessment ID
   * @param resolution The resolution description
   * @returns The updated risk assessment
   */
  async markAsResolved(id: string, resolution: string): Promise<RiskAssessment> {
    try {
      const assessment = await this.prisma.riskAssessment.update({
        where: { id },
        data: {
          resolvedAt: new Date(),
          resolution,
        },
      });
      return assessment;
    } catch (error) {
      logger.error('Error marking risk assessment as resolved', { id, error });
      throw new DatabaseError(
        'Error marking risk assessment as resolved',
        'RISK_ASSESSMENT_MARK_AS_RESOLVED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete risk assessments by user ID
   * @param userId The user ID
   * @returns Number of deleted risk assessments
   */
  async deleteByUserId(userId: string): Promise<number> {
    try {
      const result = await this.prisma.riskAssessment.deleteMany({
        where: { userId },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting risk assessments by user ID', { userId, error });
      throw new DatabaseError(
        'Error deleting risk assessments by user ID',
        'RISK_ASSESSMENT_DELETE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete risk assessments by session ID
   * @param sessionId The session ID
   * @returns Number of deleted risk assessments
   */
  async deleteBySessionId(sessionId: string): Promise<number> {
    try {
      const result = await this.prisma.riskAssessment.deleteMany({
        where: { sessionId },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting risk assessments by session ID', { sessionId, error });
      throw new DatabaseError(
        'Error deleting risk assessments by session ID',
        'RISK_ASSESSMENT_DELETE_BY_SESSION_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete resolved risk assessments older than a specified date
   * @param date The cutoff date
   * @returns Number of deleted risk assessments
   */
  async deleteResolvedOlderThan(date: Date): Promise<number> {
    try {
      const result = await this.prisma.riskAssessment.deleteMany({
        where: {
          resolvedAt: {
            not: null,
            lt: date,
          },
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting resolved risk assessments older than date', { date, error });
      throw new DatabaseError(
        'Error deleting resolved risk assessments older than date',
        'RISK_ASSESSMENT_DELETE_RESOLVED_OLDER_THAN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  protected override toWhereClause(filter?: RiskAssessmentFilterOptions): any {
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

    if (filter.sessionId) {
      where.sessionId = filter.sessionId;
    }

    if (filter.ipAddress) {
      where.ipAddress = filter.ipAddress;
    }

    if (filter.deviceId) {
      where.deviceId = filter.deviceId;
    }

    if (filter.riskLevel) {
      where.riskLevel = filter.riskLevel;
    }

    if (filter.isResolved !== undefined) {
      if (filter.isResolved) {
        where.resolvedAt = {
          not: null,
        };
      } else {
        where.resolvedAt = null;
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

    if (filter.resolvedAtBefore || filter.resolvedAtAfter) {
      where.resolvedAt = where.resolvedAt || {};

      if (filter.resolvedAtBefore) {
        where.resolvedAt.lte = filter.resolvedAtBefore;
      }

      if (filter.resolvedAtAfter) {
        where.resolvedAt.gte = filter.resolvedAtAfter;
      }
    }

    return where;
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected override withTransaction(tx: PrismaClient): BaseRepository<RiskAssessment, string> {
    return new PrismaRiskAssessmentRepository(tx);
  }
}

// Export a singleton instance
export const riskAssessmentRepository = new PrismaRiskAssessmentRepository();
