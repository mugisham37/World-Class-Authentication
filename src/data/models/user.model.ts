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
export interface User {
  id: string;
  email: string;
  emailVerified: boolean;
  username: string | null;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt: Date | null;
  status: UserStatus;
  role: UserRole;
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
  username?: string;
  emailVerified?: boolean;
  status?: UserStatus;
  role?: UserRole;
  profile?: {
    firstName?: string;
    lastName?: string;
    phone?: string;
    address?: string;
    city?: string;
    state?: string;
    country?: string;
    zipCode?: string;
    birthDate?: Date;
    bio?: string;
    avatarUrl?: string;
  };
}

/**
 * Update user data interface
 * Represents the data needed to update an existing user
 */
export interface UpdateUserData {
  email?: string;
  username?: string;
  emailVerified?: boolean;
  status?: UserStatus;
  role?: UserRole;
  lastLoginAt?: Date | null;
  profile?: {
    firstName?: string;
    lastName?: string;
    phone?: string;
    address?: string;
    city?: string;
    state?: string;
    country?: string;
    zipCode?: string;
    birthDate?: Date | null;
    bio?: string;
    avatarUrl?: string;
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
  status?: UserStatus;
  role?: UserRole;
  emailVerified?: boolean;
  createdAtBefore?: Date;
  createdAtAfter?: Date;
  updatedAtBefore?: Date;
  updatedAtAfter?: Date;
  lastLoginAtBefore?: Date;
  lastLoginAtAfter?: Date;
}
