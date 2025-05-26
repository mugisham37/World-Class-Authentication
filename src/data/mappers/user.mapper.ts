import {
  User as PrismaUser,
  UserStatus as PrismaUserStatus,
  UserRole as PrismaUserRole,
  Prisma,
} from '@prisma/client';
import {
  User,
  UserStatus,
  UserRole,
  UserWithProfile,
  CreateUserData,
  UpdateUserData,
} from '../models/user.model';

/**
 * UserMapper class
 * Handles mapping between Prisma and domain models
 */
export class UserMapper {
  /**
   * Maps a Prisma User to a domain User
   * @param prismaUser The Prisma User to map
   * @returns The domain User
   */
  static toDomain(prismaUser: PrismaUser): User {
    return {
      id: prismaUser.id,
      email: prismaUser.email,
      emailVerified: prismaUser.emailVerified,
      username: prismaUser.username,
      createdAt: prismaUser.createdAt,
      updatedAt: prismaUser.updatedAt,
      lastLoginAt: prismaUser.lastLoginAt,
      status: this.mapStatus(prismaUser.status),
      role: this.mapRole(prismaUser.role),
      active: prismaUser.active,
      lockedUntil: prismaUser.lockedUntil,
      failedLoginAttempts: prismaUser.failedLoginAttempts,
    };
  }

  /**
   * Maps a Prisma User with profile to a domain UserWithProfile
   * @param prismaUser The Prisma User with profile to map
   * @returns The domain UserWithProfile
   */
  static toDomainWithProfile(prismaUser: any): UserWithProfile {
    const user = this.toDomain(prismaUser);
    return {
      ...user,
      profile: prismaUser.profile
        ? {
            id: prismaUser.profile.id,
            userId: prismaUser.profile.userId,
            firstName: prismaUser.profile.firstName,
            lastName: prismaUser.profile.lastName,
            phone: prismaUser.profile.phone,
            address: prismaUser.profile.address,
            city: prismaUser.profile.city,
            state: prismaUser.profile.state,
            country: prismaUser.profile.country,
            zipCode: prismaUser.profile.zipCode,
            birthDate: prismaUser.profile.birthDate,
            bio: prismaUser.profile.bio,
            avatarUrl: prismaUser.profile.avatarUrl,
            createdAt: prismaUser.profile.createdAt,
            updatedAt: prismaUser.profile.updatedAt,
          }
        : null,
    };
  }

  /**
   * Maps domain CreateUserData to Prisma UserCreateInput
   * @param data The domain CreateUserData
   * @returns Prisma UserCreateInput
   */
  static toPrismaCreate(data: CreateUserData): Prisma.UserCreateInput {
    const { profile, ...userData } = data;

    return {
      ...userData,
      status: userData.status as unknown as PrismaUserStatus,
      role: userData.role as unknown as PrismaUserRole,
      profile: profile
        ? {
            create: profile,
          }
        : undefined,
    } as Prisma.UserCreateInput;
  }

  /**
   * Maps domain UpdateUserData to Prisma UserUpdateInput
   * @param data The domain UpdateUserData
   * @returns Prisma UserUpdateInput
   */
  static toPrismaUpdate(data: UpdateUserData): Prisma.UserUpdateInput {
    const { profile, ...userData } = data;

    return {
      ...userData,
      status: userData.status as unknown as PrismaUserStatus,
      role: userData.role as unknown as PrismaUserRole,
      profile: profile
        ? {
            upsert: {
              create: profile,
              update: profile,
            },
          }
        : undefined,
    } as Prisma.UserUpdateInput;
  }

  /**
   * Maps a Prisma UserStatus to a domain UserStatus
   * @param prismaStatus The Prisma UserStatus to map
   * @returns The domain UserStatus
   */
  private static mapStatus(prismaStatus: PrismaUserStatus): UserStatus {
    switch (prismaStatus) {
      case 'ACTIVE':
        return UserStatus.ACTIVE;
      case 'INACTIVE':
        return UserStatus.INACTIVE;
      case 'PENDING':
        return UserStatus.PENDING;
      case 'LOCKED':
        return UserStatus.LOCKED;
      case 'SUSPENDED':
        return UserStatus.SUSPENDED;
      default:
        return UserStatus.INACTIVE;
    }
  }

  /**
   * Maps a Prisma UserRole to a domain UserRole
   * @param prismaRole The Prisma UserRole to map
   * @returns The domain UserRole
   */
  private static mapRole(prismaRole: PrismaUserRole): UserRole {
    switch (prismaRole) {
      case 'USER':
        return UserRole.USER;
      case 'ADMIN':
        return UserRole.ADMIN;
      case 'SUPER_ADMIN':
        return UserRole.SUPER_ADMIN;
      default:
        return UserRole.USER;
    }
  }
}
