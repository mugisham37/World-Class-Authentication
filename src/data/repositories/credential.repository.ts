import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  Credential,
  CredentialType,
  CreateCredentialData,
  UpdateCredentialData,
} from '../models/credential.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';
import { prisma } from '../prisma/client';

/**
 * Credential repository interface
 * Defines credential-specific operations
 */
export interface CredentialRepository extends BaseRepository<Credential, string> {
  /**
   * Find a credential by user ID and type
   * @param userId User ID
   * @param type Credential type
   * @returns Credential or null if not found
   */
  findByUserIdAndType(userId: string, type: CredentialType): Promise<Credential | null>;

  /**
   * Find a credential by identifier
   * @param identifier Credential identifier
   * @returns Credential or null if not found
   */
  findByIdentifier(identifier: string): Promise<Credential | null>;

  /**
   * Find credentials by user ID
   * @param userId User ID
   * @returns List of credentials
   */
  findByUserId(userId: string): Promise<Credential[]>;

  /**
   * Update a credential by user ID and type
   * @param userId User ID
   * @param type Credential type
   * @param data Credential data to update
   * @returns Updated credential
   */
  updateByUserIdAndType(
    userId: string,
    type: CredentialType,
    data: UpdateCredentialData
  ): Promise<Credential>;

  /**
   * Delete a credential by user ID and type
   * @param userId User ID
   * @param type Credential type
   * @returns True if the credential was deleted, false otherwise
   */
  deleteByUserIdAndType(userId: string, type: CredentialType): Promise<boolean>;

  /**
   * Delete all credentials for a user
   * @param userId User ID
   * @returns Number of deleted credentials
   */
  deleteByUserId(userId: string): Promise<number>;

  /**
   * Update last used time for a credential
   * @param id Credential ID
   * @returns Updated credential
   */
  updateLastUsed(id: string): Promise<Credential>;

  /**
   * Check if a credential exists by identifier
   * @param identifier Credential identifier
   * @returns True if the credential exists, false otherwise
   */
  existsByIdentifier(identifier: string): Promise<boolean>;

  /**
   * Upsert a credential (create if it doesn't exist, update if it does)
   * @param userId User ID
   * @param type Credential type
   * @param data Credential data
   * @returns Created or updated credential
   */
  upsertByUserIdAndType(
    userId: string,
    type: CredentialType,
    data: CreateCredentialData
  ): Promise<Credential>;
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
   * @param userId User ID
   * @param type Credential type
   * @returns Credential or null if not found
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
   * @param identifier Credential identifier
   * @returns Credential or null if not found
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
   * @param userId User ID
   * @returns List of credentials
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
   * Update a credential by user ID and type
   * @param userId User ID
   * @param type Credential type
   * @param data Credential data to update
   * @returns Updated credential
   */
  async updateByUserIdAndType(
    userId: string,
    type: CredentialType,
    data: UpdateCredentialData
  ): Promise<Credential> {
    try {
      const credential = await this.prisma.credential.update({
        where: {
          userId_type: {
            userId,
            type,
          },
        },
        data,
      });
      return credential;
    } catch (error) {
      logger.error('Error updating credential by user ID and type', { userId, type, error });
      throw new DatabaseError(
        'Error updating credential by user ID and type',
        'CREDENTIAL_UPDATE_BY_USER_ID_AND_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete a credential by user ID and type
   * @param userId User ID
   * @param type Credential type
   * @returns True if the credential was deleted, false otherwise
   */
  async deleteByUserIdAndType(userId: string, type: CredentialType): Promise<boolean> {
    try {
      await this.prisma.credential.delete({
        where: {
          userId_type: {
            userId,
            type,
          },
        },
      });
      return true;
    } catch (error) {
      logger.error('Error deleting credential by user ID and type', { userId, type, error });

      // Check if the error is a record not found error
      if (error instanceof Error && error.message.includes('Record to delete does not exist')) {
        return false;
      }

      throw new DatabaseError(
        'Error deleting credential by user ID and type',
        'CREDENTIAL_DELETE_BY_USER_ID_AND_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Delete all credentials for a user
   * @param userId User ID
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
   * Update last used time for a credential
   * @param id Credential ID
   * @returns Updated credential
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
   * @param identifier Credential identifier
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
   * Upsert a credential (create if it doesn't exist, update if it does)
   * @param userId User ID
   * @param type Credential type
   * @param data Credential data
   * @returns Created or updated credential
   */
  async upsertByUserIdAndType(
    userId: string,
    type: CredentialType,
    data: CreateCredentialData
  ): Promise<Credential> {
    try {
      const credential = await this.prisma.credential.upsert({
        where: {
          userId_type: {
            userId,
            type,
          },
        },
        update: data,
        create: {
          ...data,
          userId,
          type,
        },
      });
      return credential;
    } catch (error) {
      logger.error('Error upserting credential by user ID and type', { userId, type, error });
      throw new DatabaseError(
        'Error upserting credential by user ID and type',
        'CREDENTIAL_UPSERT_BY_USER_ID_AND_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected withTransaction(tx: PrismaClient): BaseRepository<Credential, string> {
    return new PrismaCredentialRepository(tx);
  }
}

// Export a singleton instance
export const credentialRepository = new PrismaCredentialRepository();
