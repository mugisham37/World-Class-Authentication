/**
 * User status enum
 * Represents the status of a user in the system
 */
export enum UserStatus {
  ACTIVE = 'ACTIVE',
  INACTIVE = 'INACTIVE',
  PENDING = 'PENDING',
  LOCKED = 'LOCKED',
  SUSPENDED = 'SUSPENDED',
}

/**
 * User role enum
 * Represents the role of a user in the system
 */
export enum UserRole {
  USER = 'USER',
  ADMIN = 'ADMIN',
  SUPER_ADMIN = 'SUPER_ADMIN',
}

/**
 * User model interface
 * Represents a user in the system
 */
import { BaseUser } from "../../shared/types/user.types";

export interface User extends BaseUser {
  username: string | null;
  password: string;
  status: UserStatus;
  role: UserRole;
  active: boolean;
  lockedUntil: Date | null;
  failedLoginAttempts: number;
  lastPasswordChange?: Date | null;
  // Note: phoneNumber and lastLoginAt are inherited from BaseUser with compatible types
  // BaseUser.phoneNumber?: string is compatible with string | null
  // BaseUser.lastLoginAt?: Date is compatible with Date | null
}

/**
 * User profile model interface
 * Represents a user's profile information
 */
export interface UserProfile {
  id: string;
  userId: string;
  firstName: string | null;
  lastName: string | null;
  phone: string | null;
  address: string | null;
  city: string | null;
  state: string | null;
  country: string | null;
  zipCode: string | null;
  birthDate: Date | null;
  bio: string | null;
  avatarUrl: string | null;
  metadata?: Record<string, any> | null;
  createdAt: Date;
  updatedAt: Date;
  user?: User;
}

/**
 * User with profile model interface
 * Represents a user with their profile information
 */
export interface UserWithProfile extends User {
  profile: UserProfile | null;
}

/**
 * Create user data interface
 * Represents the data needed to create a new user
 */
export interface CreateUserData {
  email: string;
  password: string;
  username?: string | null;
  emailVerified?: boolean;
  phoneNumber?: string | null;
  phoneVerified?: boolean;
  status?: UserStatus;
  role?: UserRole;
  profile?: {
    firstName?: string | null;
    lastName?: string | null;
    phone?: string | null;
    address?: string | null;
    city?: string | null;
    state?: string | null;
    country?: string | null;
    zipCode?: string | null;
    birthDate?: Date | null;
    bio?: string | null;
    avatarUrl?: string | null;
    metadata?: Record<string, any> | null;
  };
}

/**
 * Update user data interface
 * Represents the data needed to update an existing user
 */
export interface UpdateUserData {
  email?: string;
  username?: string | null;
  password?: string;
  emailVerified?: boolean;
  phoneNumber?: string | null;
  phoneVerified?: boolean;
  status?: UserStatus;
  role?: UserRole;
  lastLoginAt?: Date | null;
  lastPasswordChange?: Date | null;
  profile?: {
    firstName?: string | null;
    lastName?: string | null;
    phone?: string | null;
    address?: string | null;
    city?: string | null;
    state?: string | null;
    country?: string | null;
    zipCode?: string | null;
    birthDate?: Date | null;
    bio?: string | null;
    avatarUrl?: string | null;
    metadata?: Record<string, any> | null;
  };
}

/**
 * User filter options interface
 * Represents the options for filtering users
 */
export interface UserFilterOptions {
  id?: string;
  email?: string;
  username?: string;
  phoneNumber?: string;
  status?: UserStatus;
  role?: UserRole;
  emailVerified?: boolean;
  phoneVerified?: boolean;
  createdAtBefore?: Date;
  createdAtAfter?: Date;
  updatedAtBefore?: Date;
  updatedAtAfter?: Date;
  lastLoginAtBefore?: Date;
  lastLoginAtAfter?: Date;
}
