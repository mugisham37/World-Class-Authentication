import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import {
  CreateUserData,
  UpdateUserData,
  User,
  UserFilterOptions,
  UserWithProfile,
} from '../models/user.model';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';

/**
 * User repository interface
 * Defines user-specific operations
 */
export interface UserRepository extends BaseRepository<User, string> {
  /**
   * Find a user by email
   * @param email The user's email
   * @returns The user or null if not found
   */
  findByEmail(email: string): Promise<User | null>;

  /**
   * Find a user by username
   * @param username The user's username
   * @returns The user or null if not found
   */
  findByUsername(username: string): Promise<User | null>;

  /**
   * Find a user with their profile
   * @param id The user ID
   * @returns The user with profile or null if not found
   */
  findWithProfile(id: string): Promise<UserWithProfile | null>;

  /**
   * Find users with their profiles
   * @param filter The filter criteria
   * @returns Array of users with profiles
   */
  findManyWithProfiles(filter?: UserFilterOptions): Promise<UserWithProfile[]>;

  /**
   * Create a user with profile
   * @param data The user data
   * @returns The created user with profile
   */
  createWithProfile(data: CreateUserData): Promise<UserWithProfile>;

  /**
   * Update a user with profile
   * @param id The user ID
   * @param data The update data
   * @returns The updated user with profile
   */
  updateWithProfile(id: string, data: UpdateUserData): Promise<UserWithProfile>;

  /**
   * Update a user's last login time
   * @param id The user ID
   * @returns The updated user
   */
  updateLastLogin(id: string): Promise<User>;
}

/**
 * Prisma implementation of the user repository
 */
export class PrismaUserRepository
  extends PrismaBaseRepository<User, string>
  implements UserRepository
{
  /**
   * The Prisma model name
   */
  protected readonly modelName = 'user';

  /**
   * Find a user by email
   * @param email The user's email
   * @returns The user or null if not found
   */
  async findByEmail(email: string): Promise<User | null> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { email },
      });
      return user;
    } catch (error) {
      logger.error('Error finding user by email', { email, error });
      throw new DatabaseError(
        'Error finding user by email',
        'USER_FIND_BY_EMAIL_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find a user by username
   * @param username The user's username
   * @returns The user or null if not found
   */
  async findByUsername(username: string): Promise<User | null> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { username },
      });
      return user;
    } catch (error) {
      logger.error('Error finding user by username', { username, error });
      throw new DatabaseError(
        'Error finding user by username',
        'USER_FIND_BY_USERNAME_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find a user with their profile
   * @param id The user ID
   * @returns The user with profile or null if not found
   */
  async findWithProfile(id: string): Promise<UserWithProfile | null> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id },
        include: { profile: true },
      });
      return user as UserWithProfile | null;
    } catch (error) {
      logger.error('Error finding user with profile', { id, error });
      throw new DatabaseError(
        'Error finding user with profile',
        'USER_FIND_WITH_PROFILE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find users with their profiles
   * @param filter The filter criteria
   * @returns Array of users with profiles
   */
  async findManyWithProfiles(filter?: UserFilterOptions): Promise<UserWithProfile[]> {
    try {
      const where = this.buildWhereClause(filter);
      const users = await this.prisma.user.findMany({
        where,
        include: { profile: true },
      });
      return users as UserWithProfile[];
    } catch (error) {
      logger.error('Error finding users with profiles', { filter, error });
      throw new DatabaseError(
        'Error finding users with profiles',
        'USER_FIND_MANY_WITH_PROFILES_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Create a user with profile
   * @param data The user data
   * @returns The created user with profile
   */
  async createWithProfile(data: CreateUserData): Promise<UserWithProfile> {
    try {
      const { profile, ...userData } = data;

      const user = await this.prisma.user.create({
        data: {
          ...userData,
          profile: profile
            ? {
                create: profile,
              }
            : undefined,
        },
        include: { profile: true },
      });

      return user as UserWithProfile;
    } catch (error) {
      logger.error('Error creating user with profile', { data, error });
      throw new DatabaseError(
        'Error creating user with profile',
        'USER_CREATE_WITH_PROFILE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update a user with profile
   * @param id The user ID
   * @param data The update data
   * @returns The updated user with profile
   */
  async updateWithProfile(id: string, data: UpdateUserData): Promise<UserWithProfile> {
    try {
      const { profile, ...userData } = data;

      // Check if user exists
      const existingUser = await this.prisma.user.findUnique({
        where: { id },
        include: { profile: true },
      });

      if (!existingUser) {
        throw new Error(`User with ID ${id} not found`);
      }

      const user = await this.prisma.user.update({
        where: { id },
        data: {
          ...userData,
          profile: profile
            ? {
                upsert: {
                  create: profile,
                  update: profile,
                },
              }
            : undefined,
        },
        include: { profile: true },
      });

      return user as UserWithProfile;
    } catch (error) {
      logger.error('Error updating user with profile', { id, data, error });
      throw new DatabaseError(
        'Error updating user with profile',
        'USER_UPDATE_WITH_PROFILE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update a user's last login time
   * @param id The user ID
   * @returns The updated user
   */
  async updateLastLogin(id: string): Promise<User> {
    try {
      const user = await this.prisma.user.update({
        where: { id },
        data: {
          lastLoginAt: new Date(),
        },
      });

      return user;
    } catch (error) {
      logger.error('Error updating user last login', { id, error });
      throw new DatabaseError(
        'Error updating user last login',
        'USER_UPDATE_LAST_LOGIN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  private buildWhereClause(filter?: UserFilterOptions): any {
    if (!filter) {
      return {};
    }

    const where: any = {};

    if (filter.id) {
      where.id = filter.id;
    }

    if (filter.email) {
      where.email = filter.email;
    }

    if (filter.username) {
      where.username = filter.username;
    }

    if (filter.status) {
      where.status = filter.status;
    }

    if (filter.role) {
      where.role = filter.role;
    }

    if (filter.emailVerified !== undefined) {
      where.emailVerified = filter.emailVerified;
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

    if (filter.lastLoginAtBefore || filter.lastLoginAtAfter) {
      where.lastLoginAt = {};

      if (filter.lastLoginAtBefore) {
        where.lastLoginAt.lte = filter.lastLoginAtBefore;
      }

      if (filter.lastLoginAtAfter) {
        where.lastLoginAt.gte = filter.lastLoginAtAfter;
      }
    }

    return where;
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected withTransaction(tx: PrismaClient): BaseRepository<User, string> {
    return new PrismaUserRepository(tx);
  }
}

// Export a singleton instance
export const userRepository = new PrismaUserRepository();
