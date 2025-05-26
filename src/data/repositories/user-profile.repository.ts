import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import { UserProfile } from '../models/user.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * User profile repository interface
 * Defines user profile-specific operations
 */
export interface UserProfileRepository extends BaseRepository<UserProfile, string> {
  /**
   * Find a user profile by user ID
   * @param userId The user ID
   * @returns The user profile or null if not found
   */
  findByUserId(userId: string): Promise<UserProfile | null>;

  /**
   * Update a user profile by user ID
   * @param userId The user ID
   * @param data The update data
   * @returns The updated user profile
   */
  updateByUserId(userId: string, data: Partial<UserProfile>): Promise<UserProfile>;
}

/**
 * Prisma implementation of the user profile repository
 */
export class PrismaUserProfileRepository
  extends PrismaBaseRepository<UserProfile, string>
  implements UserProfileRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'userProfile';

  /**
   * Find a user profile by user ID
   * @param userId The user ID
   * @returns The user profile or null if not found
   */
  async findByUserId(userId: string): Promise<UserProfile | null> {
    try {
      const profile = await this.prisma.userProfile.findUnique({
        where: { userId },
      });
      return profile;
    } catch (error) {
      logger.error('Error finding user profile by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding user profile by user ID',
        'USER_PROFILE_FIND_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update a user profile by user ID
   * @param userId The user ID
   * @param data The update data
   * @returns The updated user profile
   */
  async updateByUserId(userId: string, data: Partial<UserProfile>): Promise<UserProfile> {
    try {
      // Check if profile exists
      const existingProfile = await this.prisma.userProfile.findUnique({
        where: { userId },
      });

      if (existingProfile) {
        // Update existing profile
        return await this.prisma.userProfile.update({
          where: { userId },
          data,
        });
      } else {
        // Create new profile
        return await this.prisma.userProfile.create({
          data: {
            ...data,
            userId,
            user: {
              connect: {
                id: userId,
              },
            },
          },
        });
      }
    } catch (error) {
      logger.error('Error updating user profile by user ID', { userId, error });
      throw new DatabaseError(
        'Error updating user profile by user ID',
        'USER_PROFILE_UPDATE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected withTransaction(tx: PrismaClient): BaseRepository<UserProfile, string> {
    return new PrismaUserProfileRepository(tx);
  }
}

// Export a singleton instance
export const userProfileRepository = new PrismaUserProfileRepository();
