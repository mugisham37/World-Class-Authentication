import { PrismaClient, Prisma } from '@prisma/client';
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

  /**
   * Update a user profile by user ID with transaction support
   * @param userId The user ID
   * @param data The update data
   * @returns The updated user profile
   */
  updateByUserIdWithTransaction(userId: string, data: Partial<UserProfile>): Promise<UserProfile>;
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
   * Transform user profile data to Prisma update input
   * @param data The user profile data
   * @returns The Prisma update input
   */
  private toUpdateInput(data: Partial<UserProfile>): Prisma.UserProfileUpdateInput {
    // Validate the data before transforming
    this.validateUpdateData(data);

    // Create an object with only defined values
    const updateData: Prisma.UserProfileUpdateInput = {};

    if (data.firstName !== undefined) updateData.firstName = data.firstName;
    if (data.lastName !== undefined) updateData.lastName = data.lastName;
    if (data.phone !== undefined) updateData.phone = data.phone;
    if (data.address !== undefined) updateData.address = data.address;
    if (data.city !== undefined) updateData.city = data.city;
    if (data.state !== undefined) updateData.state = data.state;
    if (data.country !== undefined) updateData.country = data.country;
    if (data.zipCode !== undefined) updateData.zipCode = data.zipCode;
    if (data.birthDate !== undefined) updateData.birthDate = data.birthDate;
    if (data.bio !== undefined) updateData.bio = data.bio;
    if (data.avatarUrl !== undefined) updateData.avatarUrl = data.avatarUrl;

    return updateData;
  }

  /**
   * Transform user profile data to Prisma create input
   * @param data The user profile data
   * @param userId The user ID
   * @returns The Prisma create input
   */
  private toCreateInput(data: Partial<UserProfile>, userId: string): Prisma.UserProfileCreateInput {
    // Validate the data before transforming
    this.validateUpdateData(data);

    // Create an object with only defined values and required user connection
    const createData: Prisma.UserProfileCreateInput = {
      user: {
        connect: {
          id: userId,
        },
      },
    };

    if (data.firstName !== undefined) createData.firstName = data.firstName;
    if (data.lastName !== undefined) createData.lastName = data.lastName;
    if (data.phone !== undefined) createData.phone = data.phone;
    if (data.address !== undefined) createData.address = data.address;
    if (data.city !== undefined) createData.city = data.city;
    if (data.state !== undefined) createData.state = data.state;
    if (data.country !== undefined) createData.country = data.country;
    if (data.zipCode !== undefined) createData.zipCode = data.zipCode;
    if (data.birthDate !== undefined) createData.birthDate = data.birthDate;
    if (data.bio !== undefined) createData.bio = data.bio;
    if (data.avatarUrl !== undefined) createData.avatarUrl = data.avatarUrl;

    return createData;
  }

  /**
   * Validate update data to ensure only valid fields are included
   * @param data The update data
   * @throws Error if invalid fields are included
   */
  private validateUpdateData(data: Partial<UserProfile>): void {
    const allowedFields = [
      'firstName',
      'lastName',
      'phone',
      'address',
      'city',
      'state',
      'country',
      'zipCode',
      'birthDate',
      'bio',
      'avatarUrl',
    ];

    const invalidFields = Object.keys(data).filter(
      key =>
        !allowedFields.includes(key) &&
        key !== 'id' &&
        key !== 'userId' &&
        key !== 'createdAt' &&
        key !== 'updatedAt' &&
        key !== 'user'
    );

    if (invalidFields.length > 0) {
      throw new Error(`Invalid update fields: ${invalidFields.join(', ')}`);
    }
  }

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
        // Update existing profile using our helper method
        return await this.prisma.userProfile.update({
          where: { userId },
          data: this.toUpdateInput(data),
        });
      } else {
        // Create new profile using our helper method
        return await this.prisma.userProfile.create({
          data: this.toCreateInput(data, userId),
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
   * Update a user profile by user ID with transaction support
   * @param userId The user ID
   * @param data The update data
   * @returns The updated user profile
   */
  async updateByUserIdWithTransaction(
    userId: string,
    data: Partial<UserProfile>
  ): Promise<UserProfile> {
    return await this.prisma.$transaction(async tx => {
      // Create a new instance with the transaction client
      const repo = new PrismaUserProfileRepository(tx as PrismaClient);

      // Use the repository to update the profile
      return await repo.updateByUserId(userId, data);
    });
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
