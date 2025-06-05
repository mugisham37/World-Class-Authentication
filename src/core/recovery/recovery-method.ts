import { Injectable } from '@tsed/di';

/**
 * Recovery method types
 */
export enum RecoveryMethodType {
  EMAIL = 'EMAIL',
  SECURITY_QUESTIONS = 'SECURITY_QUESTIONS',
  TRUSTED_CONTACTS = 'TRUSTED_CONTACTS',
  ADMIN_RECOVERY = 'ADMIN_RECOVERY',
  RECOVERY_CODES = 'RECOVERY_CODES',
}

/**
 * Recovery initiation result interface
 * Contains data returned after initiating a recovery process
 */
export interface RecoveryInitiationResult {
  /**
   * Metadata for internal use
   */
  metadata: Record<string, any>;

  /**
   * Data to be sent to the client
   */
  clientData: Record<string, any>;
}

/**
 * Recovery verification result interface
 * Contains data returned after verifying a recovery challenge
 */
export interface RecoveryVerificationResult {
  /**
   * Whether the verification was successful
   */
  success: boolean;

  /**
   * Message describing the result
   */
  message: string;

  /**
   * Additional data (optional)
   */
  data?: Record<string, any>;
}

/**
 * Base recovery method abstract class
 * Defines the common interface for all recovery methods
 */
@Injectable()
export abstract class BaseRecoveryMethod {
  /**
   * The type of recovery method
   */
  protected abstract readonly type: RecoveryMethodType;

  /**
   * Check if the recovery method is available for a user
   * @param userId User ID
   * @param options Additional options
   * @returns True if the recovery method is available
   */
  abstract isAvailableForUser(userId: string, options?: Record<string, any>): Promise<boolean>;

  /**
   * Register the recovery method for a user
   * @param userId User ID
   * @param name Name for the recovery method
   * @param data Additional method-specific data
   * @returns ID of the created recovery method
   */
  abstract register(userId: string, name: string, data?: Record<string, any>): Promise<string>;

  /**
   * Initiate recovery using this method
   * @param userId User ID
   * @param requestId Recovery request ID
   * @param options Additional options
   * @returns Recovery data
   */
  abstract initiateRecovery(
    userId: string,
    requestId: string,
    options?: Record<string, any>
  ): Promise<RecoveryInitiationResult>;

  /**
   * Verify recovery challenge
   * @param requestId Recovery request ID
   * @param verificationData Verification data
   * @returns Verification result
   */
  abstract verifyRecovery(
    requestId: string,
    verificationData: Record<string, any>
  ): Promise<RecoveryVerificationResult>;

  /**
   * Get the type of this recovery method
   * @returns Recovery method type
   */
  getType(): RecoveryMethodType {
    return this.type;
  }
}
