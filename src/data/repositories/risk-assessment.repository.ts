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
import { prisma } from '../prisma/client';

/**
 * Risk assessment repository interface
 * Defines risk assessment-specific operations
 */
export interface RiskAssessmentRepository extends BaseRepository<RiskAssessment, string> {
  /**
   * Find risk assessments by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns List of risk assessments
   */
  findByUserId(userId: string, options?: RiskAssessmentFilterOptions): Promise<RiskAssessment[]>;

  /**
   * Find risk assessments by session ID
   * @param sessionId Session ID
   * @param options Filter options
   * @returns List of risk assessments
   */
  findBySessionId(
    sessionId: string,
    options?: RiskAssessmentFilterOptions
  ): Promise<RiskAssessment[]>;

  /**
   * Find risk assessments by IP address
   * @param ipAddress IP address
   * @param options Filter options
   * @returns List of risk assessments
   */
  findByIpAddress(
    ipAddress: string,
    options?: RiskAssessmentFilterOptions
  ): Promise<RiskAssessment[]>;

  /**
   * Find risk assessments by device ID
   * @param deviceId Device ID
   * @param options Filter options
   * @returns List of risk assessments
   */
  findByDeviceId(
    deviceId: string,
    options?: RiskAssessmentFilterOptions
  ): Promise<RiskAssessment[]>;

  /**
   * Find risk assessments by risk level
   * @param riskLevel Risk level
   * @param options Filter options
   * @returns List of risk assessments
   */
  findByRiskLevel(
    riskLevel: RiskLevel,
    options?: RiskAssessmentFilterOptions
  ): Promise<RiskAssessment[]>;

  /**
   * Find unresolved risk assessments
   * @param options Filter options
   * @returns List of unresolved risk assessments
   */
  findUnresolved(options?: RiskAssessmentFilterOptions): Promise<RiskAssessment[]>;

  /**
   * Find resolved risk assessments
   * @param options Filter options
   * @returns List of resolved risk assessments
   */
  findResolved(options?: RiskAssessmentFilterOptions): Promise<RiskAssessment[]>;

  /**
   * Find high-risk assessments
   * @param options Filter options
   * @returns List of high-risk assessments
   */
  findHighRisk(options?: RiskAssessmentFilterOptions): Promise<RiskAssessment[]>;

  /**
   * Mark a risk assessment as resolved
   * @param id Risk assessment ID
   * @param resolution Resolution description
   * @returns Updated risk assessment
   */
  markAsResolved(id: string, resolution: string): Promise<RiskAssessment>;

  /**
   * Count risk assessments by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns Number of risk assessments
   */
  countByUserId(userId: string, options?: RiskAssessmentFilterOptions): Promise<number>;

  /**
   * Count risk assessments by risk level
   * @param riskLevel Risk level
   * @param options Filter options
   * @returns Number of risk assessments
   */
  countByRiskLevel(riskLevel: RiskLevel, options?: RiskAssessmentFilterOptions): Promise<number>;

  /**
   * Count unresolved risk assessments
   * @param options Filter options
   * @returns Number of unresolved risk assessments
   */
  countUnresolved(options?: RiskAssessmentFilterOptions): Promise<number>;

  /**
   * Delete risk assessments older than a specified date
   * @param date Date threshold
   * @returns Number of deleted risk assessments
   */
  deleteOlderThan(date: Date): Promise<number>;

  /**
   * Delete resolved risk assessments older than a specified date
   * @param date Date threshold
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
   * @param userId User ID
   * @param options Filter options
   * @returns List of risk assessments
   */
  async findByUserId(
    userId: string,
    options?: RiskAssessmentFilterOptions
  ): Promise<RiskAssessment[]> {
    try {
      const where = this.buildWhereClause({ ...options, userId });
      const assessments = await this.prisma.riskAssessment.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding risk assessments by user ID', { userId, options, error });
      throw new DatabaseError(
        'Error finding risk assessments by user ID',
        'RISK_ASSESSMENT_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find risk assessments by session ID
   * @param sessionId Session ID
   * @param options Filter options
   * @returns List of risk assessments
   */
  async findBySessionId(
    sessionId: string,
    options?: RiskAssessmentFilterOptions
  ): Promise<RiskAssessment[]> {
    try {
      const where = this.buildWhereClause({ ...options, sessionId });
      const assessments = await this.prisma.riskAssessment.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding risk assessments by session ID', { sessionId, options, error });
      throw new DatabaseError(
        'Error finding risk assessments by session ID',
        'RISK_ASSESSMENT_FIND_BY_SESSION_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find risk assessments by IP address
   * @param ipAddress IP address
   * @param options Filter options
   * @returns List of risk assessments
   */
  async findByIpAddress(
    ipAddress: string,
    options?: RiskAssessmentFilterOptions
  ): Promise<RiskAssessment[]> {
    try {
      const where = this.buildWhereClause({ ...options, ipAddress });
      const assessments = await this.prisma.riskAssessment.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding risk assessments by IP address', { ipAddress, options, error });
      throw new DatabaseError(
        'Error finding risk assessments by IP address',
        'RISK_ASSESSMENT_FIND_BY_IP_ADDRESS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find risk assessments by device ID
   * @param deviceId Device ID
   * @param options Filter options
   * @returns List of risk assessments
   */
  async findByDeviceId(
    deviceId: string,
    options?: RiskAssessmentFilterOptions
  ): Promise<RiskAssessment[]> {
    try {
      const where = this.buildWhereClause({ ...options, deviceId });
      const assessments = await this.prisma.riskAssessment.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding risk assessments by device ID', { deviceId, options, error });
      throw new DatabaseError(
        'Error finding risk assessments by device ID',
        'RISK_ASSESSMENT_FIND_BY_DEVICE_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find risk assessments by risk level
   * @param riskLevel Risk level
   * @param options Filter options
   * @returns List of risk assessments
   */
  async findByRiskLevel(
    riskLevel: RiskLevel,
    options?: RiskAssessmentFilterOptions
  ): Promise<RiskAssessment[]> {
    try {
      const where = this.buildWhereClause({ ...options, riskLevel });
      const assessments = await this.prisma.riskAssessment.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding risk assessments by risk level', { riskLevel, options, error });
      throw new DatabaseError(
        'Error finding risk assessments by risk level',
        'RISK_ASSESSMENT_FIND_BY_RISK_LEVEL_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find unresolved risk assessments
   * @param options Filter options
   * @returns List of unresolved risk assessments
   */
  async findUnresolved(options?: RiskAssessmentFilterOptions): Promise<RiskAssessment[]> {
    try {
      const where = this.buildWhereClause({ ...options, isResolved: false });
      const assessments = await this.prisma.riskAssessment.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding unresolved risk assessments', { options, error });
      throw new DatabaseError(
        'Error finding unresolved risk assessments',
        'RISK_ASSESSMENT_FIND_UNRESOLVED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find resolved risk assessments
   * @param options Filter options
   * @returns List of resolved risk assessments
   */
  async findResolved(options?: RiskAssessmentFilterOptions): Promise<RiskAssessment[]> {
    try {
      const where = this.buildWhereClause({ ...options, isResolved: true });
      const assessments = await this.prisma.riskAssessment.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding resolved risk assessments', { options, error });
      throw new DatabaseError(
        'Error finding resolved risk assessments',
        'RISK_ASSESSMENT_FIND_RESOLVED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find high-risk assessments
   * @param options Filter options
   * @returns List of high-risk assessments
   */
  async findHighRisk(options?: RiskAssessmentFilterOptions): Promise<RiskAssessment[]> {
    try {
      // Create a custom where clause for high risk levels
      const where = this.buildWhereClause(options);
      // Add the risk level condition directly
      where.riskLevel = { in: [RiskLevel.HIGH, RiskLevel.CRITICAL] };
      const assessments = await this.prisma.riskAssessment.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return assessments;
    } catch (error) {
      logger.error('Error finding high-risk assessments', { options, error });
      throw new DatabaseError(
        'Error finding high-risk assessments',
        'RISK_ASSESSMENT_FIND_HIGH_RISK_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Mark a risk assessment as resolved
   * @param id Risk assessment ID
   * @param resolution Resolution description
   * @returns Updated risk assessment
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
      logger.error('Error marking risk assessment as resolved', { id, resolution, error });
      throw new DatabaseError(
        'Error marking risk assessment as resolved',
        'RISK_ASSESSMENT_MARK_AS_RESOLVED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count risk assessments by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns Number of risk assessments
   */
  async countByUserId(userId: string, options?: RiskAssessmentFilterOptions): Promise<number> {
    try {
      const where = this.buildWhereClause({ ...options, userId });
      const count = await this.prisma.riskAssessment.count({
        where,
      });
      return count;
    } catch (error) {
      logger.error('Error counting risk assessments by user ID', { userId, options, error });
      throw new DatabaseError(
        'Error counting risk assessments by user ID',
        'RISK_ASSESSMENT_COUNT_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count risk assessments by risk level
   * @param riskLevel Risk level
   * @param options Filter options
   * @returns Number of risk assessments
   */
  async countByRiskLevel(
    riskLevel: RiskLevel,
    options?: RiskAssessmentFilterOptions
  ): Promise<number> {
    try {
      const where = this.buildWhereClause({ ...options, riskLevel });
      const count = await this.prisma.riskAssessment.count({
        where,
      });
      return count;
    } catch (error) {
      logger.error('Error counting risk assessments by risk level', { riskLevel, options, error });
      throw new DatabaseError(
        'Error counting risk assessments by risk level',
        'RISK_ASSESSMENT_COUNT_BY_RISK_LEVEL_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count unresolved risk assessments
   * @param options Filter options
   * @returns Number of unresolved risk assessments
   */
  async countUnresolved(options?: RiskAssessmentFilterOptions): Promise<number> {
    try {
      const where = this.buildWhereClause({ ...options, isResolved: false });
      const count = await this.prisma.riskAssessment.count({
        where,
      });
      return count;
    } catch (error) {
      logger.error('Error counting unresolved risk assessments', { options, error });
      throw new DatabaseError(
        'Error counting unresolved risk assessments',
        'RISK_ASSESSMENT_COUNT_UNRESOLVED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete risk assessments older than a specified date
   * @param date Date threshold
   * @returns Number of deleted risk assessments
   */
  async deleteOlderThan(date: Date): Promise<number> {
    try {
      const result = await this.prisma.riskAssessment.deleteMany({
        where: {
          createdAt: { lt: date },
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting risk assessments older than date', { date, error });
      throw new DatabaseError(
        'Error deleting risk assessments older than date',
        'RISK_ASSESSMENT_DELETE_OLDER_THAN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete resolved risk assessments older than a specified date
   * @param date Date threshold
   * @returns Number of deleted risk assessments
   */
  async deleteResolvedOlderThan(date: Date): Promise<number> {
    try {
      const result = await this.prisma.riskAssessment.deleteMany({
        where: {
          resolvedAt: { not: null, lt: date },
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
  private buildWhereClause(filter?: RiskAssessmentFilterOptions): any {
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

    // Boolean filters
    if (filter.isResolved !== undefined) {
      if (filter.isResolved) {
        where.resolvedAt = { not: null };
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
  protected withTransaction(tx: PrismaClient): BaseRepository<RiskAssessment, string> {
    return new PrismaRiskAssessmentRepository(tx);
  }
}

// Export a singleton instance
export const riskAssessmentRepository = new PrismaRiskAssessmentRepository();
