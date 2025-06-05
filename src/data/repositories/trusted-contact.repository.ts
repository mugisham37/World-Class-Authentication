import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  mapToDomainTrustedContact,
  mapToPrismaCreateData,
  mapToPrismaStatus,
  mapToPrismaUpdateData,
} from '../mappers/trusted-contact.mapper';
import {
  TrustedContact,
  TrustedContactFilterOptions,
  TrustedContactStatus,
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
   * Transform a Prisma trusted contact to a domain trusted contact
   * @param contact The Prisma trusted contact
   * @returns The domain trusted contact or null if not found
   */
  private transformContact(contact: any): TrustedContact | null {
    return mapToDomainTrustedContact(contact);
  }

  /**
   * Transform an array of Prisma trusted contacts to domain trusted contacts
   * @param contacts The Prisma trusted contacts
   * @returns The domain trusted contacts
   */
  private transformContacts(contacts: any[]): TrustedContact[] {
    return contacts.map(contact => this.transformContact(contact)!).filter(Boolean);
  }

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
      return this.transformContacts(contacts);
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
          status: mapToPrismaStatus(TrustedContactStatus.ACTIVE),
        },
        orderBy: { createdAt: 'desc' },
      });
      return this.transformContacts(contacts);
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
      return this.transformContact(contact);
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
          status: mapToPrismaStatus(status),
        },
        orderBy: { createdAt: 'desc' },
      });
      return this.transformContacts(contacts);
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
          status: mapToPrismaStatus(TrustedContactStatus.ACTIVE),
          verifiedAt: new Date(),
        },
      });
      return this.transformContact(contact)!;
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
        data: { status: mapToPrismaStatus(status) },
      });
      return this.transformContact(contact)!;
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
          status: mapToPrismaStatus(TrustedContactStatus.ACTIVE),
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
      where.status = mapToPrismaStatus(filter.status);
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
   * Override the create method to transform the result
   * @param data The data to create
   * @returns The created entity
   */
  override async create(data: Partial<TrustedContact>): Promise<TrustedContact> {
    try {
      // Convert domain data to Prisma data
      const createData = mapToPrismaCreateData(data);
      
      const result = await this.prisma[this.modelName].create({
        data: createData,
      });
      return this.transformContact(result)!;
    } catch (error) {
      logger.error(`Error creating ${this.modelName}`, { data, error });
      throw new DatabaseError(
        `Error creating ${this.modelName}`,
        `${this.modelName.toUpperCase()}_CREATE_ERROR`,
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Override the update method to transform the result
   * @param id The entity ID
   * @param data The data to update
   * @returns The updated entity
   */
  override async update(id: string, data: Partial<TrustedContact>): Promise<TrustedContact> {
    try {
      // Convert domain data to Prisma data
      const updateData = mapToPrismaUpdateData(data);
      
      const result = await this.prisma[this.modelName].update({
        where: { id },
        data: updateData,
      });
      return this.transformContact(result)!;
    } catch (error) {
      logger.error(`Error updating ${this.modelName}`, { id, data, error });
      throw new DatabaseError(
        `Error updating ${this.modelName}`,
        `${this.modelName.toUpperCase()}_UPDATE_ERROR`,
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Override the findById method to transform the result
   * @param id The entity ID
   * @returns The entity or null if not found
   */
  override async findById(id: string): Promise<TrustedContact | null> {
    try {
      const result = await this.prisma[this.modelName].findUnique({
        where: { id },
      });
      return this.transformContact(result);
    } catch (error) {
      logger.error(`Error finding ${this.modelName} by ID`, { id, error });
      throw new DatabaseError(
        `Error finding ${this.modelName} by ID`,
        `${this.modelName.toUpperCase()}_FIND_BY_ID_ERROR`,
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Override the findAll method to transform the results
   * @param options The query options
   * @returns Array of entities
   */
  override async findAll(options?: any): Promise<TrustedContact[]> {
    // Convert options to TrustedContactFilterOptions if needed
    const filter = options as TrustedContactFilterOptions;
    try {
      const results = await this.prisma[this.modelName].findMany({
        where: this.toWhereClause(filter),
        orderBy: { createdAt: 'desc' },
      });
      return this.transformContacts(results);
    } catch (error) {
      logger.error(`Error finding all ${this.modelName}`, { filter, error });
      throw new DatabaseError(
        `Error finding all ${this.modelName}`,
        `${this.modelName.toUpperCase()}_FIND_ALL_ERROR`,
        error instanceof Error ? error : undefined
      );
    }
  }

  protected override withTransaction(tx: PrismaClient): BaseRepository<TrustedContact, string> {
    return new PrismaTrustedContactRepository(tx);
  }
}

// Export a singleton instance
export const trustedContactRepository = new PrismaTrustedContactRepository();
