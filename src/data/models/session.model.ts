/**
 * Session model interface
 * Represents a user session in the system
 */
export interface Session {
  id: string;
  userId: string;
  token: string;
  refreshToken?: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  deviceId: string | null;
  deviceType?: string | null;
  location: string | null;
  createdAt: Date;
  updatedAt: Date;
  expiresAt: Date;
  lastActiveAt: Date;
  isRevoked: boolean;
  revokedAt?: Date | null;
  revocationReason: string | null;
}

/**
 * Create session data interface
 * Represents the data needed to create a new session
 */
export interface CreateSessionData {
  userId: string;
  token: string;
  refreshToken?: string;
  ipAddress: string | null;
  userAgent: string | null;
  deviceId?: string | null;
  deviceType?: string | null;
  location?: string | null;
  expiresAt: Date;
  lastActiveAt?: Date;
  isRevoked?: boolean;
  user?: {
    connect: {
      id: string;
    };
  };
}

/**
 * Update session data interface
 * Represents the data needed to update an existing session
 */
export interface UpdateSessionData {
  refreshToken?: string;
  expiresAt?: Date;
  lastActiveAt?: Date;
  revokedAt?: Date;
  revocationReason?: string;
}

/**
 * Session filter options interface
 * Represents the options for filtering sessions
 */
export interface SessionFilterOptions {
  id?: string;
  userId?: string;
  token?: string;
  refreshToken?: string;
  deviceId?: string;
  ipAddress?: string;
  isActive?: boolean;
  isRevoked?: boolean;
  createdAtBefore?: Date;
  createdAtAfter?: Date;
  updatedAtBefore?: Date;
  updatedAtAfter?: Date;
  expiresAtBefore?: Date;
  expiresAtAfter?: Date;
  lastActiveAtBefore?: Date;
  lastActiveAtAfter?: Date;
  revokedAtBefore?: Date;
  revokedAtAfter?: Date;
}
