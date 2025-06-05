/**
 * Base User interface
 * Shared user properties across the application
 */
export interface BaseUser {
  id: string;
  email: string | undefined;
  phoneNumber?: string; // Using optional property instead of string | null
  emailVerified?: boolean;
  phoneVerified?: boolean;
  displayName?: string;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt?: Date;
}
