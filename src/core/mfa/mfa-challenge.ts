import type { MfaFactorType } from './mfa-factor-types';

/**
 * MFA challenge interface
 * Represents a challenge generated for MFA verification
 */
export interface MfaChallenge {
  /**
   * Unique identifier for the challenge
   */
  id: string;

  /**
   * The ID of the factor this challenge is for
   */
  factorId: string;

  /**
   * The type of MFA factor
   */
  factorType: MfaFactorType;

  /**
   * The challenge token or code
   */
  challenge: string;

  /**
   * When the challenge expires
   */
  expiresAt: Date;

  /**
   * When the challenge was created
   */
  createdAt: Date;

  /**
   * When the challenge was completed (if applicable)
   */
  completedAt?: Date;

  /**
   * The user's response to the challenge (if applicable)
   */
  response?: string;

  /**
   * Number of verification attempts
   */
  attempts: number;

  /**
   * Additional metadata specific to the factor type
   */
  metadata?: Record<string, any>;
}
