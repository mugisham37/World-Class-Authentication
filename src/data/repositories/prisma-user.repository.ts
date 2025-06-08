import {
  User as PrismaUser,
  UserProfile as PrismaUserProfile,
  Credential,
  CredentialType,
} from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';
import { Session } from '../models/session.model';
import { User, UserFilterOptions, UserProfile } from '../models/user.model';
import { executeInTransaction, TransactionClient } from '../types/prisma-types';
import { BaseRepository } from './base.repository';
import { PrismaBaseRepository } from './prisma-base.repository';
import { UserRepository } from './user.repository';

/**
 * Mapper function to convert Prisma User to application User
 * @param prismaUser The Prisma User object
 * @param passwordCredential Optional password credential
 * @returns The application User object
 */
function mapPrismaUserToModel(prismaUser: PrismaUser & { credentials?: Credential[] }): User {
  // Find password credential if available
  const passwordCredential = prismaUser.credentials?.find(
    (cred: Credential) => cred.type === ('PASSWORD' as CredentialType)
  );

  return {
    id: prismaUser.id,
    email: prismaUser.email,
    username: prismaUser.username,
    // Use credential secret as password or a placeholder if not available
    password: passwordCredential?.secret || '', // Provide password from credentials
    emailVerified: prismaUser.emailVerified,
    // Map optional properties safely
    phoneNumber: (prismaUser as any).phoneNumber || null,
    phoneVerified: (prismaUser as any).phoneVerified || false,
    status: prismaUser.status as any,
    role: prismaUser.role as any,
    active: prismaUser.active,
    lockedUntil: prismaUser.lockedUntil,
    failedLoginAttempts: prismaUser.failedLoginAttempts,
    createdAt: prismaUser.createdAt,
    updatedAt: prismaUser.updatedAt,
    lastLoginAt: prismaUser.lastLoginAt || undefined,
    lastPasswordChange: passwordCredential?.updatedAt || null,
  };
}

/**
 * Mapper function to convert Prisma UserProfile to application UserProfile
 * @param prismaProfile The Prisma UserProfile object
 * @returns The application UserProfile object
 */
function mapPrismaProfileToModel(prismaProfile: PrismaUserProfile): UserProfile {
  return {
    id: prismaProfile.id,
    userId: prismaProfile.userId,
    firstName: prismaProfile.firstName,
    lastName: prismaProfile.lastName,
    phone: prismaProfile.phone,
    address: prismaProfile.address,
    city: prismaProfile.city,
    state: prismaProfile.state,
    country: prismaProfile.country,
    zipCode: prismaProfile.zipCode,
    birthDate: prismaProfile.birthDate,
    bio: prismaProfile.bio,
    avatarUrl: prismaProfile.avatarUrl,
    createdAt: prismaProfile.createdAt,
    updatedAt: prismaProfile.updatedAt,
  };
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
   * Find user by ID
   * @param id User ID
   * @returns The user or null if not found
   */
  override async findById(id: string): Promise<User | null> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id },
        include: {
          credentials: {
            where: {
              type: 'PASSWORD',
            },
          },
        },
      });
      return user ? mapPrismaUserToModel(user) : null;
    } catch (error) {
      logger.error('Error finding user by ID', { id, error });
      throw new DatabaseError(
        'Error finding user by ID',
        'USER_FIND_BY_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find user by email
   * @param email User email
   * @returns The user or null if not found
   */
  async findByEmail(email: string): Promise<User | null> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { email },
        include: {
          credentials: {
            where: {
              type: 'PASSWORD',
            },
          },
        },
      });
      return user ? mapPrismaUserToModel(user) : null;
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
   * Find user by phone number
   * @param phone User phone number
   * @returns The user or null if not found
   */
  async findByPhone(phone: string): Promise<User | null> {
    try {
      const user = await this.prisma.user.findFirst({
        where: {
          // Use type assertion to handle potential schema differences
          phoneNumber: phone,
        } as any,
        include: {
          credentials: {
            where: {
              type: 'PASSWORD',
            },
          },
        },
      });
      return user ? mapPrismaUserToModel(user) : null;
    } catch (error) {
      logger.error('Error finding user by phone', { phone, error });
      throw new DatabaseError(
        'Error finding user by phone',
        'USER_FIND_BY_PHONE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find user by username
   * @param username Username
   * @returns The user or null if not found
   */
  async findByUsername(username: string): Promise<User | null> {
    try {
      const user = await this.prisma.user.findFirst({
        where: { username },
        include: {
          credentials: {
            where: {
              type: 'PASSWORD',
            },
          },
        },
      });
      return user ? mapPrismaUserToModel(user) : null;
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
   * Increment failed login attempts
   * @param id User ID
   * @returns The updated user
   */
  async incrementFailedLoginAttempts(id: string): Promise<User> {
    try {
      const user = await this.prisma.user.update({
        where: { id },
        data: {
          failedLoginAttempts: {
            increment: 1,
          },
        },
        include: {
          credentials: {
            where: {
              type: 'PASSWORD',
            },
          },
        },
      });
      return mapPrismaUserToModel(user);
    } catch (error) {
      logger.error('Error incrementing failed login attempts', { id, error });
      throw new DatabaseError(
        'Error incrementing failed login attempts',
        'USER_INCREMENT_FAILED_LOGIN_ATTEMPTS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Reset failed login attempts
   * @param id User ID
   * @returns The updated user
   */
  async resetFailedLoginAttempts(id: string): Promise<User> {
    try {
      const user = await this.prisma.user.update({
        where: { id },
        data: {
          failedLoginAttempts: 0,
        },
        include: {
          credentials: {
            where: {
              type: 'PASSWORD',
            },
          },
        },
      });
      return mapPrismaUserToModel(user);
    } catch (error) {
      logger.error('Error resetting failed login attempts', { id, error });
      throw new DatabaseError(
        'Error resetting failed login attempts',
        'USER_RESET_FAILED_LOGIN_ATTEMPTS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update last login time
   * @param id User ID
   * @returns The updated user
   */
  async updateLastLogin(id: string): Promise<User> {
    try {
      const user = await this.prisma.user.update({
        where: { id },
        data: {
          lastLoginAt: new Date(),
        },
        include: {
          credentials: {
            where: {
              type: 'PASSWORD',
            },
          },
        },
      });
      return mapPrismaUserToModel(user);
    } catch (error) {
      logger.error('Error updating last login time', { id, error });
      throw new DatabaseError(
        'Error updating last login time',
        'USER_UPDATE_LAST_LOGIN_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find user profile by user ID
   * @param userId User ID
   * @returns The user profile or null if not found
   */
  async findProfileByUserId(userId: string): Promise<UserProfile | null> {
    try {
      const profile = await this.prisma.userProfile.findUnique({
        where: { userId },
      });
      return profile ? mapPrismaProfileToModel(profile) : null;
    } catch (error) {
      logger.error('Error finding user profile by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding user profile by user ID',
        'USER_FIND_PROFILE_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find user sessions by user ID
   * @param userId User ID
   * @returns Array of user sessions
   */
  async findSessionsByUserId(userId: string): Promise<Session[]> {
    try {
      const sessions = await this.prisma.session.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
      });
      return sessions as Session[];
    } catch (error) {
      logger.error('Error finding user sessions by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding user sessions by user ID',
        'USER_FIND_SESSIONS_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Find user preferences by user ID
   * @param userId User ID
   * @returns User preferences or null if not found
   */
  async findPreferencesByUserId(userId: string): Promise<any | null> {
    try {
      // Since userPreferences might not exist in the Prisma schema,
      // we'll return a mock implementation for now
      // In a real implementation, this would query the actual preferences table
      return { userId, preferences: {} };
    } catch (error) {
      logger.error('Error finding user preferences by user ID', { userId, error });
      throw new DatabaseError(
        'Error finding user preferences by user ID',
        'USER_FIND_PREFERENCES_BY_USER_ID_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Anonymize user profile
   * @param userId User ID
   */
  async anonymizeProfile(userId: string): Promise<void> {
    try {
      await this.prisma.userProfile.update({
        where: { userId },
        data: {
          firstName: null,
          lastName: null,
          phone: null,
          address: null,
          city: null,
          state: null,
          country: null,
          zipCode: null,
          birthDate: null,
          bio: null,
          avatarUrl: null,
        },
      });
    } catch (error) {
      logger.error('Error anonymizing user profile', { userId, error });
      throw new DatabaseError(
        'Error anonymizing user profile',
        'USER_ANONYMIZE_PROFILE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Anonymize user sessions
   * @param userId User ID
   */
  async anonymizeSessions(userId: string): Promise<void> {
    try {
      await this.prisma.session.updateMany({
        where: { userId },
        data: {
          ipAddress: null,
          userAgent: null,
          // Remove metadata if it's not in the schema
        },
      });
    } catch (error) {
      logger.error('Error anonymizing user sessions', { userId, error });
      throw new DatabaseError(
        'Error anonymizing user sessions',
        'USER_ANONYMIZE_SESSIONS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Reset user password
   * @param userId User ID
   * @param newPassword New password (should be hashed before saving)
   */
  async resetPassword(userId: string, newPassword: string): Promise<void> {
    try {
      // First, update the user to reset failed login attempts and unlock the account
      const user = await this.prisma.user.update({
        where: { id: userId },
        data: {
          failedLoginAttempts: 0, // Reset failed attempts
          lockedUntil: null, // Unlock account if locked
        },
        include: {
          credentials: {
            where: {
              type: 'PASSWORD',
            },
          },
        },
      });

      // Find the password credential
      const passwordCredential = user.credentials.find(
        (cred: Credential) => cred.type === ('PASSWORD' as CredentialType)
      );

      if (passwordCredential) {
        // Update the password credential
        await this.prisma.credential.update({
          where: { id: passwordCredential.id },
          data: {
            secret: newPassword,
            updatedAt: new Date(),
          },
        });
      } else {
        // Create a new password credential if one doesn't exist
        await this.prisma.credential.create({
          data: {
            userId,
            type: 'PASSWORD' as CredentialType,
            identifier: user.email,
            secret: newPassword,
          },
        });
      }

      // No need to return anything as the method signature is Promise<void>
    } catch (error) {
      logger.error('Error resetting password', { userId, error });
      throw new DatabaseError(
        'Error resetting password',
        'USER_RESET_PASSWORD_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Create a new user
   * @param data User data
   * @returns The created user
   */
  override async create(data: Partial<User>): Promise<User> {
    try {
      // Extract password from data
      const { password, ...userData } = data;

      // Create user in transaction to ensure atomicity
      // Use executeInTransaction helper to handle type compatibility
      return await executeInTransaction(this.prisma, async (tx: TransactionClient) => {
        // Create the user
        const user = await tx.user.create({
          data: userData as any,
          include: {
            credentials: {
              where: {
                type: 'PASSWORD',
              },
            },
          },
        });

        // Create password credential if password is provided
        if (password) {
          await tx.credential.create({
            data: {
              userId: user.id,
              type: 'PASSWORD' as CredentialType,
              identifier: user.email,
              secret: password,
            },
          });
        }

        // Fetch the user with credentials
        const createdUser = await tx.user.findUnique({
          where: { id: user.id },
          include: {
            credentials: {
              where: {
                type: 'PASSWORD',
              },
            },
          },
        });

        return mapPrismaUserToModel(createdUser!);
      });
    } catch (error) {
      logger.error('Error creating user', { error });
      throw new DatabaseError(
        'Error creating user',
        'USER_CREATE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Update user data
   * @param id User ID
   * @param data User data to update
   * @returns The updated user
   */
  override async update(id: string, data: Partial<User>): Promise<User> {
    try {
      // Extract password from data
      const { password, ...userData } = data;

      // Update user in transaction to ensure atomicity
      // Use executeInTransaction helper to handle type compatibility
      return await executeInTransaction(this.prisma, async (tx: TransactionClient) => {
        // Update the user
        const user = await tx.user.update({
          where: { id },
          data: userData as any,
          include: {
            credentials: {
              where: {
                type: 'PASSWORD',
              },
            },
          },
        });

        // Update password credential if password is provided
        if (password) {
          const passwordCredential = user.credentials.find(
            (cred: Credential) => cred.type === ('PASSWORD' as CredentialType)
          );

          if (passwordCredential) {
            // Update existing password credential
            await tx.credential.update({
              where: { id: passwordCredential.id },
              data: {
                secret: password,
                updatedAt: new Date(),
              },
            });
          } else {
            // Create new password credential
            await tx.credential.create({
              data: {
                userId: user.id,
                type: 'PASSWORD' as CredentialType,
                identifier: user.email,
                secret: password,
              },
            });
          }
        }

        // Fetch the updated user with credentials
        const updatedUser = await tx.user.findUnique({
          where: { id },
          include: {
            credentials: {
              where: {
                type: 'PASSWORD',
              },
            },
          },
        });

        return mapPrismaUserToModel(updatedUser!);
      });
    } catch (error) {
      logger.error('Error updating user', { id, error });
      throw new DatabaseError(
        'Error updating user',
        'USER_UPDATE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Build a where clause from filter options
   * @param filter The filter options
   * @returns The Prisma where clause
   */
  protected override toWhereClause(filter?: UserFilterOptions): any {
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

    if (filter.phoneNumber) {
      where.phoneNumber = filter.phoneNumber;
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

    if (filter.phoneVerified !== undefined) {
      where.phoneVerified = filter.phoneVerified;
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
  protected override withTransaction(tx: TransactionClient): BaseRepository<User, string> {
    // Create a new repository instance with the transaction client
    return new PrismaUserRepository(tx);
  }
}

// Export the interface from the original file
export { UserRepository } from './user.repository';

// Export a singleton instance
export const userRepository = new PrismaUserRepository();
