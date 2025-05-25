import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  TrustedContact,
  TrustedContactStatus,
  CreateTrustedContactData,
  UpdateTrustedContactData,
  TrustedContactFilterOptions,
} from '../models/trusted-contact.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * Trusted contact repository interface
 * Defines trusted contact-specific operations
 */
export interface TrustedContactRepository extends BaseRepository<TrustedContact, string> {
  /**
   * Find trusted contacts by user ID
   * @param userId The user ID
   * @returns Array of trusted contacts
   */
  findByUserId(userId: string): Promise<TrustedContact[]>;

  /**
   * Find active trusted contacts by user ID
   * @param userId The user ID
   * @returns Array of active trusted contacts
   */
  findActiveByUserId(userId: string): Promise<TrustedContact[]>;

  /**
   * Find a trusted contact by email
   * @param email The email address
   * @returns The trusted contact or null if not found
   */
  findByEmail(email: string): Promise<TrustedContact | null>;

  /**
   * Find trusted contacts by user ID and status
   * @param userId The user ID
   * @param status The trusted contact status
   * @returns Array of trusted contacts
   */
  findByUserIdAndStatus(userId: string, status: TrustedContactStatus): Promise<TrustedContact[]>;

  /**
   * Mark a trusted contact as verified
   * @param id The trusted contact ID
   * @returns The updated trusted contact
   */
  markAsVerified(id: string): Promise<TrustedContact>;

  /**
   * Change a trusted contact's status
   * @param id The trusted contact ID
   * @param status The new status
   * @returns The updated trusted contact
   */
  changeStatus(id: string, status: TrustedContactStatus): Promise<TrustedContact>;

  /**
   * Delete trusted contacts by user ID
   * @param userId The user ID
   * @returns Number of deleted trusted contacts
   */
  deleteByUserId(userId: string): Promise<number>;

  /**
   * Count trusted contacts by user ID
   * @param userId The user ID
   * @returns Number of trusted contacts
   */
  countByUserId(userId: string): Promise<number>;

  /**
   * Count active trusted contacts by user ID
   * @param userId The user ID
   * @returns Number of active trusted contacts
   */
  countActiveByUserId(userId: string): Promise<number>;
}

/**
 * Prisma implementation of the trusted contact repository
 */
export class PrismaTrustedContactRepository
  extends PrismaBaseRepository<TrustedContact, string>
  implements TrustedContactRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'trustedContact';

  /**
   * Find trusted contacts by user ID
   * @param userId The user ID
   * @returns Array of trusted contacts
   */
  async findByUserId(userId: string): Promise<TrustedContact[]> {
    try {
      const contacts = await this.prisma.trustedContact.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
      });
      return contacts;
    } catch (error) {
      logger.error('Error finding trusted contacts by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding trusted contacts by user ID',
        'TRUSTED_CONTACT_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find active trusted contacts by user ID
   * @param userId The user ID
   * @returns Array of active trusted contacts
   */
  async findActiveByUserId(userId: string): Promise<TrustedContact[]> {
    try {
      const contacts = await this.prisma.trustedContact.findMany({
        where: {
          userId,
          status: TrustedContactStatus.ACTIVE,
        },
        orderBy: { createdAt: 'desc' },
      });
      return contacts;
    } catch (error) {
      logger.error('Error finding active trusted contacts by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding active trusted contacts by user ID',
        'TRUSTED_CONTACT_FIND_ACTIVE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find a trusted contact by email
   * @param email The email address
   * @returns The trusted contact or null if not found
   */
  async findByEmail(email: string): Promise<TrustedContact | null> {
    try {
      const contact = await this.prisma.trustedContact.findFirst({
        where: { email },
      });
      return contact;
    } catch (error) {
      logger.error('Error finding trusted contact by email', { email, error });
      throw new DatabaseError(
        'Error finding trusted contact by email',
        'TRUSTED_CONTACT_FIND_BY_EMAIL_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find trusted contacts by user ID and status
   * @param userId The user ID
   * @param status The trusted contact status
   * @returns Array of trusted contacts
   */
  async findByUserIdAndStatus(
    userId: string,
    status: TrustedContactStatus
  ): Promise<TrustedContact[]> {
    try {
      const contacts = await this.prisma.trustedContact.findMany({
        where: {
          userId,
          status,
        },
        orderBy: { createdAt: 'desc' },
      });
      return contacts;
    } catch (error) {
      logger.error('Error finding trusted contacts by user ID and status', {
        userId,
        status,
        error,
      });
      throw new DatabaseError(
        'Error finding trusted contacts by user ID and status',
        'TRUSTED_CONTACT_FIND_BY_USER_ID_AND_STATUS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Mark a trusted contact as verified
   * @param id The trusted contact ID
   * @returns The updated trusted contact
   */
  async markAsVerified(id: string): Promise<TrustedContact> {
    try {
      const contact = await this.prisma.trustedContact.update({
        where: { id },
        data: {
          status: TrustedContactStatus.ACTIVE,
          verifiedAt: new Date(),
        },
      });
      return contact;
    } catch (error) {
      logger.error('Error marking trusted contact as verified', { id, error });
      throw new DatabaseError(
        'Error marking trusted contact as verified',
        'TRUSTED_CONTACT_MARK_AS_VERIFIED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Change a trusted contact's status
   * @param id The trusted contact ID
   * @param status The new status
   * @returns The updated trusted contact
   */
  async changeStatus(id: string, status: TrustedContactStatus): Promise<TrustedContact> {
    try {
      const contact = await this.prisma.trustedContact.update({
        where: { id },
        data: { status },
      });
      return contact;
    } catch (error) {
      logger.error('Error changing trusted contact status', { id, status, error });
      throw new DatabaseError(
        'Error changing trusted contact status',
        'TRUSTED_CONTACT_CHANGE_STATUS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete trusted contacts by user ID
   * @param userId The user ID
   * @returns Number of deleted trusted contacts
   */
  async deleteByUserId(userId: string): Promise<number> {
    try {
      const result = await this.prisma.trustedContact.deleteMany({
        where: { userId },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting trusted contacts by user ID', { userId, error });
      throw new DatabaseError(
        'Error deleting trusted contacts by user ID',
        'TRUSTED_CONTACT_DELETE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count trusted contacts by user ID
   * @param userId The user ID
   * @returns Number of trusted contacts
   */
  async countByUserId(userId: string): Promise<number> {
    try {
      const count = await this.prisma.trustedContact.count({
        where: { userId },
      });
      return count;
    } catch (error) {
      logger.error('Error counting trusted contacts by user ID', { userId, error });
      throw new DatabaseError(
        'Error counting trusted contacts by user ID',
        'TRUSTED_CONTACT_COUNT_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Count active trusted contacts by user ID
   * @param userId The user ID
   * @returns Number of active trusted contacts
   */
  async countActiveByUserId(userId: string): Promise<number> {
    try {
      const count = await this.prisma.trustedContact.count({
        where: {
          userId,
          status: TrustedContactStatus.ACTIVE,
        },
      });
      return count;
    } catch (error) {
      logger.error('Error counting active trusted contacts by user ID', { userId, error });
      throw new DatabaseError(
        'Error counting active trusted contacts by user ID',
        'TRUSTED_CONTACT_COUNT_ACTIVE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  protected override toWhereClause(filter?: TrustedContactFilterOptions): any {
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

    if (filter.email) {
      where.email = filter.email;
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

    if (filter.updatedAtBefore || filter.updatedAtAfter) {
      where.updatedAt = {};

      if (filter.updatedAtBefore) {
        where.updatedAt.lte = filter.updatedAtBefore;
      }

      if (filter.updatedAtAfter) {
        where.updatedAt.gte = filter.updatedAtAfter;
      }
    }

    if (filter.verifiedAtBefore || filter.verifiedAtAfter) {
      where.verifiedAt = {};

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
  protected override withTransaction(tx: PrismaClient): BaseRepository<TrustedContact, string> {
    return new PrismaTrustedContactRepository(tx);
  }
}

// Export a singleton instance
export const trustedContactRepository = new PrismaTrustedContactRepository();
