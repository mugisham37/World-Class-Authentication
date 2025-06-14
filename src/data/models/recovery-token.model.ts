/**
 * Recovery token type enum
 * Represents the type of recovery token in the system
 */
export enum RecoveryTokenType {
  PASSWORD_RESET = 'password-reset',
  EMAIL_VERIFICATION = 'email-verification',
  ACCOUNT_RECOVERY = 'account-recovery',
  MFA_RECOVERY = 'mfa-recovery',
}

/**
 * Recovery token model interface
 * Represents a recovery token in the system
 */
export interface RecoveryToken {
  id: string;
  token: string;
  type: RecoveryTokenType;
  userId: string; // Changed from optional to required
  email?: string | null;
  expiresAt: Date;
  usedAt?: Date | null;
  createdAt: Date;
  metadata?: Record<string, any> | null;
}

/**
 * Create recovery token data interface
 * Represents the data needed to create a new recovery token
 */
export interface CreateRecoveryTokenData {
  token: string;
  type: RecoveryTokenType;
  userId: string; // Changed from optional to required
  email?: string;
  expiresAt: Date;
  metadata?: Record<string, any>;
}

/**
 * Update recovery token data interface
 * Represents the data needed to update an existing recovery token
 */
export interface UpdateRecoveryTokenData {
  usedAt?: Date;
  metadata?: Record<string, any>;
}

/**
 * Recovery token filter options interface
 * Represents the options for filtering recovery tokens
 */
export interface RecoveryTokenFilterOptions {
  id?: string;
  token?: string;
  type?: RecoveryTokenType;
  userId?: string;
  email?: string;
  isUsed?: boolean;
  isExpired?: boolean;
  createdAtBefore?: Date;
  createdAtAfter?: Date;
  expiresAtBefore?: Date;
  expiresAtAfter?: Date;
  usedAtBefore?: Date;
  usedAtAfter?: Date;
}
