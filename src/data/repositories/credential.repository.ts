import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  Credential,
  CredentialType,
  CreateCredentialData,
  UpdateCredentialData,
  CredentialFilterOptions,
} from '../models/credential.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * Credential repository interface
 * Defines credential-specific operations
 */
export interface CredentialRepository extends BaseRepository<Credential, string> {
  /**
   * Find a credential by user ID and type
   * @param userId The user ID
   * @param type The credential type
   * @returns The credential or null if not found
   */
  findByUserIdAndType(userId: string, type: CredentialType): Promise<Credential | null>;

  /**
   * Find a credential by identifier
   * @param identifier The credential identifier
   * @returns The credential or null if not found
   */
  findByIdentifier(identifier: string): Promise<Credential | null>;

  /**
   * Find credentials by user ID
   * @param userId The user ID
   * @returns Array of credentials
   */
  findByUserId(userId: string): Promise<Credential[]>;

  /**
   * Update a credential's last used time
   * @param id The credential ID
   * @returns The updated credential
   */
  updateLastUsed(id: string): Promise<Credential>;

  /**
   * Check if a credential exists by identifier
   * @param identifier The credential identifier
   * @returns True if the credential exists, false otherwise
   */
  existsByIdentifier(identifier: string): Promise<boolean>;

  /**
   * Delete credentials by user ID
   * @param userId The user ID
   * @returns Number of deleted credentials
   */
  deleteByUserId(userId: string): Promise<number>;

  /**
   * Delete expired credentials
   * @returns Number of deleted credentials
   */
  deleteExpired(): Promise<number>;
}

/**
 * Prisma implementation of the credential repository
 */
export class PrismaCredentialRepository
  extends PrismaBaseRepository<Credential, string>
  implements CredentialRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'credential';

  /**
   * Find a credential by user ID and type
   * @param userId The user ID
   * @param type The credential type
   * @returns The credential or null if not found
   */
  async findByUserIdAndType(userId: string, type: CredentialType): Promise<Credential | null> {
    try {
      const credential = await this.prisma.credential.findUnique({
        where: {
          userId_type: {
            userId,
            type,
          },
        },
      });
      return credential;
    } catch (error) {
      logger.error('Error finding credential by user ID and type', { userId, type, error });
      throw new DatabaseError(
        'Error finding credential by user ID and type',
        'CREDENTIAL_FIND_BY_USER_ID_AND_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find a credential by identifier
   * @param identifier The credential identifier
   * @returns The credential or null if not found
   */
  async findByIdentifier(identifier: string): Promise<Credential | null> {
    try {
      const credential = await this.prisma.credential.findFirst({
        where: { identifier },
      });
      return credential;
    } catch (error) {
      logger.error('Error finding credential by identifier', { identifier, error });
      throw new DatabaseError(
        'Error finding credential by identifier',
        'CREDENTIAL_FIND_BY_IDENTIFIER_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find credentials by user ID
   * @param userId The user ID
   * @returns Array of credentials
   */
  async findByUserId(userId: string): Promise<Credential[]> {
    try {
      const credentials = await this.prisma.credential.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
      });
      return credentials;
    } catch (error) {
      logger.error('Error finding credentials by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding credentials by user ID',
        'CREDENTIAL_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update a credential's last used time
   * @param id The credential ID
   * @returns The updated credential
   */
  async updateLastUsed(id: string): Promise<Credential> {
    try {
      const credential = await this.prisma.credential.update({
        where: { id },
        data: {
          lastUsedAt: new Date(),
        },
      });
      return credential;
    } catch (error) {
      logger.error('Error updating credential last used time', { id, error });
      throw new DatabaseError(
        'Error updating credential last used time',
        'CREDENTIAL_UPDATE_LAST_USED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check if a credential exists by identifier
   * @param identifier The credential identifier
   * @returns True if the credential exists, false otherwise
   */
  async existsByIdentifier(identifier: string): Promise<boolean> {
    try {
      const count = await this.prisma.credential.count({
        where: { identifier },
      });
      return count > 0;
    } catch (error) {
      logger.error('Error checking if credential exists by identifier', { identifier, error });
      throw new DatabaseError(
        'Error checking if credential exists by identifier',
        'CREDENTIAL_EXISTS_BY_IDENTIFIER_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete credentials by user ID
   * @param userId The user ID
   * @returns Number of deleted credentials
   */
  async deleteByUserId(userId: string): Promise<number> {
    try {
      const result = await this.prisma.credential.deleteMany({
        where: { userId },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting credentials by user ID', { userId, error });
      throw new DatabaseError(
        'Error deleting credentials by user ID',
        'CREDENTIAL_DELETE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete expired credentials
   * @returns Number of deleted credentials
   */
  async deleteExpired(): Promise<number> {
    try {
      const result = await this.prisma.credential.deleteMany({
        where: {
          expiresAt: {
            lt: new Date(),
          },
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error deleting expired credentials', { error });
      throw new DatabaseError(
        'Error deleting expired credentials',
        'CREDENTIAL_DELETE_EXPIRED_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  protected override toWhereClause(filter?: CredentialFilterOptions): any {
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

    if (filter.identifier) {
      where.identifier = filter.identifier;
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

    if (filter.expiresAtBefore || filter.expiresAtAfter) {
      where.expiresAt = {};

      if (filter.expiresAtBefore) {
        where.expiresAt.lte = filter.expiresAtBefore;
      }

      if (filter.expiresAtAfter) {
        where.expiresAt.gte = filter.expiresAtAfter;
      }
    }

    return where;
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected override withTransaction(tx: PrismaClient): BaseRepository<Credential, string> {
    return new PrismaCredentialRepository(tx);
  }
}

// Export a singleton instance
export const credentialRepository = new PrismaCredentialRepository();
