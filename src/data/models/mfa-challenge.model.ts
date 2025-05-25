/**
 * MFA challenge status enum
 * Represents the status of an MFA challenge in the system
 */
export enum MfaChallengeStatus {
  PENDING = 'PENDING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  EXPIRED = 'EXPIRED',
}

/**
 * MFA challenge model interface
 * Represents an MFA challenge in the system
 */
export interface MfaChallenge {
  id: string;
  factorId: string;
  challenge: string;
  response?: string | null;
  expiresAt: Date;
  createdAt: Date;
  completedAt?: Date | null;
  status: MfaChallengeStatus;
  attempts: number;
  metadata?: Record<string, any> | null;
}

/**
 * Create MFA challenge data interface
 * Represents the data needed to create a new MFA challenge
 */
export interface CreateMfaChallengeData {
  factorId: string;
  challenge: string;
  expiresAt: Date;
  metadata?: Record<string, any>;
}

/**
 * Update MFA challenge data interface
 * Represents the data needed to update an existing MFA challenge
 */
export interface UpdateMfaChallengeData {
  response?: string;
  completedAt?: Date;
  status?: MfaChallengeStatus;
  attempts?: number;
  metadata?: Record<string, any>;
}

/**
 * MFA challenge filter options interface
 * Represents the options for filtering MFA challenges
 */
export interface MfaChallengeFilterOptions {
  id?: string;
  factorId?: string;
  status?: MfaChallengeStatus;
  createdAtBefore?: Date;
  createdAtAfter?: Date;
  expiresAtBefore?: Date;
  expiresAtAfter?: Date;
  completedAtBefore?: Date;
  completedAtAfter?: Date;
}

/**
 * MFA challenge verification result interface
 * Represents the result of verifying an MFA challenge
 */
export interface MfaChallengeVerificationResult {
  success: boolean;
  challenge: MfaChallenge;
  message?: string;
}
