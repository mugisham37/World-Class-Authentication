import { PrismaClient, MfaFactor as PrismaMfaFactor, MfaFactorType as PrismaMfaFactorType, MfaFactorStatus as PrismaMfaFactorStatus } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  MfaFactor,
  MfaFactorType,
  MfaFactorStatus,
  MfaFactorFilterOptions,
} from '../models/mfa-factor.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * MFA factor repository interface
 * Defines MFA factor-specific operations
 */
export interface MfaFactorRepository extends BaseRepository<MfaFactor, string> {
  /**
   * Find MFA factors by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns List of MFA factors
   */
  findByUserId(userId: string, options?: MfaFactorFilterOptions): Promise<MfaFactor[]>;

  /**
   * Find active MFA factors by user ID
   * @param userId User ID
   * @returns List of active MFA factors
   */
  findActiveByUserId(userId: string): Promise<MfaFactor[]>;

  /**
   * Find MFA factors by user ID and type
   * @param userId User ID
   * @param type MFA factor type
   * @returns List of MFA factors
   */
  findByUserIdAndType(userId: string, type: MfaFactorType): Promise<MfaFactor[]>;

  /**
   * Find an MFA factor by credential ID
   * @param credentialId Credential ID
   * @returns MFA factor or null if not found
   */
  findByCredentialId(credentialId: string): Promise<MfaFactor | null>;

  /**
   * Find an MFA factor by phone number
   * @param phoneNumber Phone number
   * @returns MFA factor or null if not found
   */
  findByPhoneNumber(phoneNumber: string): Promise<MfaFactor | null>;

  /**
   * Find an MFA factor by email
   * @param email Email
   * @returns MFA factor or null if not found
   */
  findByEmail(email: string): Promise<MfaFactor | null>;

  /**
   * Find an MFA factor by device token
   * @param deviceToken Device token
   * @returns MFA factor or null if not found
   */
  findByDeviceToken(deviceToken: string): Promise<MfaFactor | null>;

  /**
   * Update an MFA factor's status
   * @param id MFA factor ID
   * @param status New status
   * @returns Updated MFA factor
   */
  updateStatus(id: string, status: MfaFactorStatus): Promise<MfaFactor>;

  /**
   * Mark an MFA factor as verified
   * @param id MFA factor ID
   * @returns Updated MFA factor
   */
  markAsVerified(id: string): Promise<MfaFactor>;

  /**
   * Update an MFA factor's last used time
   * @param id MFA factor ID
   * @returns Updated MFA factor
   */
  updateLastUsed(id: string): Promise<MfaFactor>;

  /**
   * Delete MFA factors by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns Number of deleted MFA factors
   */
  deleteByUserId(userId: string, options?: MfaFactorFilterOptions): Promise<number>;

  /**
   * Count MFA factors by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns Number of MFA factors
   */
  countByUserId(userId: string, options?: MfaFactorFilterOptions): Promise<number>;

  /**
   * Check if a user has any active MFA factors
   * @param userId User ID
   * @returns True if the user has active MFA factors, false otherwise
   */
  hasActiveMfaFactors(userId: string): Promise<boolean>;
}

/**
 * Prisma implementation of the MFA factor repository
 */
export class PrismaMfaFactorRepository
  extends PrismaBaseRepository<MfaFactor, string>
  implements MfaFactorRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'mfaFactor';

  /**
   * Maps a Prisma MFA factor to a domain MFA factor
   * @param prismaMfaFactor Prisma MFA factor
   * @returns Domain MFA factor
   */
  protected mapToDomainModel(prismaMfaFactor: PrismaMfaFactor): MfaFactor {
    return {
      id: prismaMfaFactor.id,
      createdAt: prismaMfaFactor.createdAt,
      updatedAt: prismaMfaFactor.updatedAt,
      userId: prismaMfaFactor.userId,
      type: this.mapToDomainType(prismaMfaFactor.type),
      name: prismaMfaFactor.name,
      secret: prismaMfaFactor.secret,
      credentialId: prismaMfaFactor.credentialId,
      phoneNumber: prismaMfaFactor.phoneNumber,
      email: prismaMfaFactor.email,
      deviceToken: prismaMfaFactor.deviceToken,
      metadata: prismaMfaFactor.metadata as Record<string, any> | null,
      verifiedAt: prismaMfaFactor.verifiedAt,
      lastUsedAt: prismaMfaFactor.lastUsedAt,
      status: this.mapToDomainStatus(prismaMfaFactor.status)
    };
  }

  /**
   * Maps a domain MFA factor type to a Prisma MFA factor type
   * @param domainType Domain MFA factor type
   * @returns Prisma MFA factor type
   */
  protected mapToPrismaType(domainType: MfaFactorType): PrismaMfaFactorType {
    switch (domainType) {
      case MfaFactorType.TOTP:
        return 'TOTP';
      case MfaFactorType.WEBAUTHN:
        return 'WEBAUTHN';
      case MfaFactorType.SMS:
        return 'SMS';
      case MfaFactorType.EMAIL:
        return 'EMAIL';
      case MfaFactorType.RECOVERY_CODE:
        return 'RECOVERY_CODE';
      case MfaFactorType.PUSH_NOTIFICATION:
        return 'PUSH_NOTIFICATION';
      default:
        throw new Error(`Unknown MFA factor type: ${domainType}`);
    }
  }

  /**
   * Maps a Prisma MFA factor type to a domain MFA factor type
   * @param prismaType Prisma MFA factor type
   * @returns Domain MFA factor type
   */
  protected mapToDomainType(prismaType: PrismaMfaFactorType): MfaFactorType {
    switch (prismaType) {
      case 'TOTP':
        return MfaFactorType.TOTP;
      case 'WEBAUTHN':
        return MfaFactorType.WEBAUTHN;
      case 'SMS':
        return MfaFactorType.SMS;
      case 'EMAIL':
        return MfaFactorType.EMAIL;
      case 'RECOVERY_CODE':
        return MfaFactorType.RECOVERY_CODE;
      case 'PUSH_NOTIFICATION':
        return MfaFactorType.PUSH_NOTIFICATION;
      default:
        throw new Error(`Unknown MFA factor type: ${prismaType}`);
    }
  }

  /**
   * Maps a domain MFA factor status to a Prisma MFA factor status
   * @param domainStatus Domain MFA factor status
   * @returns Prisma MFA factor status
   */
  protected mapToPrismaStatus(domainStatus: MfaFactorStatus): PrismaMfaFactorStatus {
    switch (domainStatus) {
      case MfaFactorStatus.ACTIVE:
        return 'ACTIVE';
      case MfaFactorStatus.PENDING:
        return 'PENDING';
      case MfaFactorStatus.DISABLED:
        return 'DISABLED';
      case MfaFactorStatus.REVOKED:
        return 'REVOKED';
      default:
        throw new Error(`Unknown MFA factor status: ${domainStatus}`);
    }
  }

  /**
   * Maps a Prisma MFA factor status to a domain MFA factor status
   * @param prismaStatus Prisma MFA factor status
   * @returns Domain MFA factor status
   */
  protected mapToDomainStatus(prismaStatus: PrismaMfaFactorStatus): MfaFactorStatus {
    switch (prismaStatus) {
      case 'ACTIVE':
        return MfaFactorStatus.ACTIVE;
      case 'PENDING':
        return MfaFactorStatus.PENDING;
      case 'DISABLED':
        return MfaFactorStatus.DISABLED;
      case 'REVOKED':
        return MfaFactorStatus.REVOKED;
      default:
        throw new Error(`Unknown MFA factor status: ${prismaStatus}`);
    }
  }

  /**
   * Find MFA factors by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns List of MFA factors
   */
  async findByUserId(userId: string, options?: MfaFactorFilterOptions): Promise<MfaFactor[]> {
    try {
      const where = this.buildWhereClause({ ...options, userId });
      const factors = await this.prisma.mfaFactor.findMany({
        where,
        orderBy: { createdAt: 'desc' },
      });
      return factors.map(factor => this.mapToDomainModel(factor));
    } catch (error) {
      logger.error('Error finding MFA factors by user ID', { userId, options, error });
      throw new DatabaseError(
        'Error finding MFA factors by user ID',
        'MFA_FACTOR_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find active MFA factors by user ID
   * @param userId User ID
   * @returns List of active MFA factors
   */
  async findActiveByUserId(userId: string): Promise<MfaFactor[]> {
    try {
      const factors = await this.prisma.mfaFactor.findMany({
        where: {
          userId,
          status: this.mapToPrismaStatus(MfaFactorStatus.ACTIVE),
        },
        orderBy: { createdAt: 'desc' },
      });
      return factors.map(factor => this.mapToDomainModel(factor));
    } catch (error) {
      logger.error('Error finding active MFA factors by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding active MFA factors by user ID',
        'MFA_FACTOR_FIND_ACTIVE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find MFA factors by user ID and type
   * @param userId User ID
   * @param type MFA factor type
   * @returns List of MFA factors
   */
  async findByUserIdAndType(userId: string, type: MfaFactorType): Promise<MfaFactor[]> {
    try {
      const factors = await this.prisma.mfaFactor.findMany({
        where: {
          userId,
          type: this.mapToPrismaType(type),
        },
        orderBy: { createdAt: 'desc' },
      });
      return factors.map(factor => this.mapToDomainModel(factor));
    } catch (error) {
      logger.error('Error finding MFA factors by user ID and type', { userId, type, error });
      throw new DatabaseError(
        'Error finding MFA factors by user ID and type',
        'MFA_FACTOR_FIND_BY_USER_ID_AND_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find an MFA factor by credential ID
   * @param credentialId Credential ID
   * @returns MFA factor or null if not found
   */
  async findByCredentialId(credentialId: string): Promise<MfaFactor | null> {
    try {
      const factor = await this.prisma.mfaFactor.findFirst({
        where: { credentialId },
      });
      return factor ? this.mapToDomainModel(factor) : null;
    } catch (error) {
      logger.error('Error finding MFA factor by credential ID', { credentialId, error });
      throw new DatabaseError(
        'Error finding MFA factor by credential ID',
        'MFA_FACTOR_FIND_BY_CREDENTIAL_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find an MFA factor by phone number
   * @param phoneNumber Phone number
   * @returns MFA factor or null if not found
   */
  async findByPhoneNumber(phoneNumber: string): Promise<MfaFactor | null> {
    try {
      const factor = await this.prisma.mfaFactor.findFirst({
        where: { phoneNumber },
      });
      return factor ? this.mapToDomainModel(factor) : null;
    } catch (error) {
      logger.error('Error finding MFA factor by phone number', { phoneNumber, error });
      throw new DatabaseError(
        'Error finding MFA factor by phone number',
        'MFA_FACTOR_FIND_BY_PHONE_NUMBER_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find an MFA factor by email
   * @param email Email
   * @returns MFA factor or null if not found
   */
  async findByEmail(email: string): Promise<MfaFactor | null> {
    try {
      const factor = await this.prisma.mfaFactor.findFirst({
        where: { email },
      });
      return factor ? this.mapToDomainModel(factor) : null;
    } catch (error) {
      logger.error('Error finding MFA factor by email', { email, error });
      throw new DatabaseError(
        'Error finding MFA factor by email',
        'MFA_FACTOR_FIND_BY_EMAIL_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find an MFA factor by device token
   * @param deviceToken Device token
   * @returns MFA factor or null if not found
   */
  async findByDeviceToken(deviceToken: string): Promise<MfaFactor | null> {
    try {
      const factor = await this.prisma.mfaFactor.findFirst({
        where: { deviceToken },
      });
      return factor ? this.mapToDomainModel(factor) : null;
    } catch (error) {
      logger.error('Error finding MFA factor by device token', { deviceToken, error });
      throw new DatabaseError(
        'Error finding MFA factor by device token',
        'MFA_FACTOR_FIND_BY_DEVICE_TOKEN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update an MFA factor's status
   * @param id MFA factor ID
   * @param status New status
   * @returns Updated MFA factor
   */
  async updateStatus(id: string, status: MfaFactorStatus): Promise<MfaFactor> {
    try {
      const factor = await this.prisma.mfaFactor.update({
        where: { id },
        data: { status: this.mapToPrismaStatus(status) },
      });
      return this.mapToDomainModel(factor);
    } catch (error) {
      logger.error('Error updating MFA factor status', { id, status, error });
      throw new DatabaseError(
        'Error updating MFA factor status',
        'MFA_FACTOR_UPDATE_STATUS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Mark an MFA factor as verified
   * @param id MFA factor ID
   * @returns Updated MFA factor
   */
  async markAsVerified(id: string): Promise<MfaFactor> {
    try {
      const factor = await this.prisma.mfaFactor.update({
        where: { id },
        data: {
          verifiedAt: new Date(),
          status: this.mapToPrismaStatus(MfaFactorStatus.ACTIVE),
        },
      });
      return this.mapToDomainModel(factor);
    } catch (error) {
      logger.error('Error marking MFA factor as verified', { id, error });
      throw new DatabaseError(
        'Error marking MFA factor as verified',
        'MFA_FACTOR_MARK_AS_VERIFIED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update an MFA factor's last used time
   * @param id MFA factor ID
   * @returns Updated MFA factor
   */
  async updateLastUsed(id: string): Promise<MfaFactor> {
    try {
      const factor = await this.prisma.mfaFactor.update({
        where: { id },
        data: {
          lastUsedAt: new Date(),
        },
      });
      return this.mapToDomainModel(factor);
    } catch (error) {
      logger.error('Error updating MFA factor last used time', { id, error });
      throw new DatabaseError(
        'Error updating MFA factor last used time',
        'MFA_FACTOR_UPDATE_LAST_USED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete MFA factors by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns Number of deleted MFA factors
   */
  async deleteByUserId(userId: string, options?: MfaFactorFilterOptions): Promise<number> {
    try {
      const where = this.buildWhereClause({ ...options, userId });
      const result = await this.prisma.mfaFactor.deleteMany({
        where,
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting MFA factors by user ID', { userId, options, error });
      throw new DatabaseError(
        'Error deleting MFA factors by user ID',
        'MFA_FACTOR_DELETE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count MFA factors by user ID
   * @param userId User ID
   * @param options Filter options
   * @returns Number of MFA factors
   */
  async countByUserId(userId: string, options?: MfaFactorFilterOptions): Promise<number> {
    try {
      const where = this.buildWhereClause({ ...options, userId });
      const count = await this.prisma.mfaFactor.count({
        where,
      });
      return count;
    } catch (error) {
      logger.error('Error counting MFA factors by user ID', { userId, options, error });
      throw new DatabaseError(
        'Error counting MFA factors by user ID',
        'MFA_FACTOR_COUNT_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check if a user has any active MFA factors
   * @param userId User ID
   * @returns True if the user has active MFA factors, false otherwise
   */
  async hasActiveMfaFactors(userId: string): Promise<boolean> {
    try {
      const count = await this.prisma.mfaFactor.count({
        where: {
          userId,
          status: MfaFactorStatus.ACTIVE,
        },
      });
      return count > 0;
    } catch (error) {
      logger.error('Error checking if user has active MFA factors', { userId, error });
      throw new DatabaseError(
        'Error checking if user has active MFA factors',
        'MFA_FACTOR_HAS_ACTIVE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  private buildWhereClause(filter?: MfaFactorFilterOptions): any {
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

    if (filter.type) {
      where.type = filter.type;
    }

    if (filter.status) {
      where.status = filter.status;
    }

    if (filter.verifiedOnly) {
      where.verifiedAt = { not: null };
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

    if (filter.lastUsedAtBefore || filter.lastUsedAtAfter) {
      where.lastUsedAt = {};

      if (filter.lastUsedAtBefore) {
        where.lastUsedAt.lte = filter.lastUsedAtBefore;
      }

      if (filter.lastUsedAtAfter) {
        where.lastUsedAt.gte = filter.lastUsedAtAfter;
      }
    }

    if (filter.verifiedAtBefore || filter.verifiedAtAfter) {
      where.verifiedAt = where.verifiedAt || {};

      if (filter.verifiedAtBefore) {
        where.verifiedAt.lte = filter.verifiedAtBefore;
      }

      if (filter.verifiedAtAfter) {
        where.verifiedAt.gte = filter.verifiedAtAfter;
      }
    }

    return where;
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected withTransaction(tx: PrismaClient): BaseRepository<MfaFactor, string> {
    return new PrismaMfaFactorRepository(tx);
  }
}

// Export a singleton instance
export const mfaFactorRepository = new PrismaMfaFactorRepository();
