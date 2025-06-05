import type { PrismaClient, Credential as PrismaCredential } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import type {
  Credential,
  CredentialType,
} from '../models/credential.model';
import type { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * Credential repository interface
 * Defines credential-specific operations
 */
export interface CredentialRepository extends BaseRepository<Credential, string> {
  /**
   * Find credentials by user ID and type
   * @param userId The user ID
   * @param type The credential type
   * @returns Array of credentials
   */
  findByUserIdAndType(userId: string, type: CredentialType): Promise<Credential[]>;

  /**
   * Find a credential by user ID, type, and identifier
   * @param userId The user ID
   * @param type The credential type
   * @param identifier The credential identifier
   * @returns The credential or null if not found
   */
  findByUserIdTypeAndIdentifier(
    userId: string,
    type: CredentialType,
    identifier: string
  ): Promise<Credential | null>;

  /**
   * Find all credentials for a user
   * @param userId The user ID
   * @returns Array of credentials
   */
  findByUserId(userId: string): Promise<Credential[]>;

  /**
   * Update credential last used time
   * @param id The credential ID
   * @returns The updated credential
   */
  updateLastUsed(id: string): Promise<Credential>;

  /**
   * Delete all credentials for a user
   * @param userId The user ID
   * @returns Number of deleted credentials
   */
  deleteByUserId(userId: string): Promise<number>;

  /**
   * Delete credentials by user ID and type
   * @param userId The user ID
   * @param type The credential type
   * @returns Number of deleted credentials
   */
  deleteByUserIdAndType(userId: string, type: CredentialType): Promise<number>;
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
   * Maps a Prisma credential to a domain model credential
   * @param prismaCredential The Prisma credential
   * @returns The domain model credential
   */
  protected mapToDomainModel(prismaCredential: PrismaCredential): Credential {
    return {
      ...prismaCredential,
      type: prismaCredential.type as CredentialType
    };
  }

  /**
   * Find credentials by user ID and type
   * @param userId The user ID
   * @param type The credential type
   * @returns Array of credentials
   */
  async findByUserIdAndType(userId: string, type: CredentialType): Promise<Credential[]> {
    try {
      const credentials = await this.prisma.credential.findMany({
        where: {
          userId,
          type,
        },
        orderBy: {
          createdAt: 'desc',
        },
      });

      return credentials.map(credential => this.mapToDomainModel(credential));
    } catch (error) {
      logger.error('Error finding credentials by user ID and type', { userId, type, error });
      throw new DatabaseError(
        'Error finding credentials by user ID and type',
        'CREDENTIAL_FIND_BY_USER_ID_AND_TYPE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find a credential by user ID, type, and identifier
   * @param userId The user ID
   * @param type The credential type
   * @param identifier The credential identifier
   * @returns The credential or null if not found
   */
  async findByUserIdTypeAndIdentifier(
    userId: string,
    type: CredentialType,
    identifier: string
  ): Promise<Credential | null> {
    try {
      const credential = await this.prisma.credential.findFirst({
        where: {
          userId,
          type,
          identifier,
        },
      });

      return credential ? this.mapToDomainModel(credential) : null;
    } catch (error) {
      logger.error('Error finding credential by user ID, type, and identifier', {
        userId,
        type,
        identifier,
        error,
      });
      throw new DatabaseError(
        'Error finding credential by user ID, type, and identifier',
        'CREDENTIAL_FIND_BY_USER_ID_TYPE_AND_IDENTIFIER_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find all credentials for a user
   * @param userId The user ID
   * @returns Array of credentials
   */
  async findByUserId(userId: string): Promise<Credential[]> {
    try {
      const credentials = await this.prisma.credential.findMany({
        where: {
          userId,
        },
        orderBy: {
          createdAt: 'desc',
        },
      });

      return credentials.map(credential => this.mapToDomainModel(credential));
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
   * Update credential last used time
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

      return this.mapToDomainModel(credential);
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
   * Delete all credentials for a user
   * @param userId The user ID
   * @returns Number of deleted credentials
   */
  async deleteByUserId(userId: string): Promise<number> {
    try {
      const result = await this.prisma.credential.deleteMany({
        where: {
          userId,
        },
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
   * Delete credentials by user ID and type
   * @param userId The user ID
   * @param type The credential type
   * @returns Number of deleted credentials
   */
  async deleteByUserIdAndType(userId: string, type: CredentialType): Promise<number> {
    try {
      const result = await this.prisma.credential.deleteMany({
        where: {
          userId,
          type,
        },
      });

      return result.count;
    } catch (error) {
      logger.error('Error deleting credentials by user ID and type', { userId, type, error });
      throw new DatabaseError(
        'Error deleting credentials by user ID and type',
        'CREDENTIAL_DELETE_BY_USER_ID_AND_TYPE_ERROR',
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
