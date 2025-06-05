/**
 * PasswordlessSession model interface
 * Represents a passwordless authentication session
 */
export interface PasswordlessSession {
  id: string;
  userId: string;
  method: string;
  identifier: string;
  challengeId: string;
  expiresAt: Date;
  isRegistration: boolean;
  completedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  metadata: any;
}

/**
 * Create passwordless session data interface
 */
export interface CreatePasswordlessSessionData {
  id?: string;
  userId: string;
  method: string;
  identifier: string;
  challengeId: string;
  expiresAt: Date;
  isRegistration?: boolean;
  completedAt?: Date | null;
  metadata?: any;
}

/**
 * Update passwordless session data interface
 */
export interface UpdatePasswordlessSessionData {
  method?: string;
  identifier?: string;
  expiresAt?: Date;
  completedAt?: Date | null;
  metadata?: any;
}

/**
 * Passwordless session query options interface
 */
export interface PasswordlessSessionQueryOptions {
  limit?: number;
  method?: string;
  isRegistration?: boolean;
  isCompleted?: boolean;
}
