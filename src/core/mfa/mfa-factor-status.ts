/**
 * MFA factor status
 * Represents the current status of an MFA factor
 */
export enum MfaFactorStatus {
  /**
   * Factor is active and can be used for authentication
   */
  ACTIVE = "ACTIVE",

  /**
   * Factor is pending activation/verification
   */
  PENDING = "PENDING",

  /**
   * Factor is temporarily disabled
   */
  DISABLED = "DISABLED",

  /**
   * Factor has been permanently revoked
   */
  REVOKED = "REVOKED",
}

/**
 * MFA challenge status
 * Represents the current status of an MFA challenge
 */
export enum MfaChallengeStatus {
  /**
   * Challenge is pending response
   */
  PENDING = "PENDING",

  /**
   * Challenge was successfully completed
   */
  COMPLETED = "COMPLETED",

  /**
   * Challenge failed (incorrect response)
   */
  FAILED = "FAILED",

  /**
   * Challenge expired before completion
   */
  EXPIRED = "EXPIRED",
}
