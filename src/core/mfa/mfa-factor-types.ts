/**
 * Enum representing the different types of MFA factors
 */
export enum MfaFactorType {
  TOTP = 'TOTP', // Time-based One-Time Password (Google Authenticator, Authy)
  WEBAUTHN = 'WEBAUTHN', // WebAuthn/FIDO2 (Security keys, biometrics)
  SMS = 'SMS', // SMS verification codes
  EMAIL = 'EMAIL', // Email verification codes
  RECOVERY_CODE = 'RECOVERY_CODE', // Backup recovery codes
  PUSH_NOTIFICATION = 'PUSH_NOTIFICATION', // Push notifications to mobile devices
}

/**
 * Enum representing the status of an MFA factor
 */
export enum MfaFactorStatus {
  ACTIVE = 'ACTIVE', // Factor is active and can be used
  PENDING = 'PENDING', // Factor is pending activation/verification
  DISABLED = 'DISABLED', // Factor is temporarily disabled
  REVOKED = 'REVOKED', // Factor has been permanently revoked
}

/**
 * Enum representing the status of an MFA challenge
 */
export enum MfaChallengeStatus {
  PENDING = 'PENDING', // Challenge is pending response
  COMPLETED = 'COMPLETED', // Challenge was successfully completed
  FAILED = 'FAILED', // Challenge failed (incorrect response)
  EXPIRED = 'EXPIRED', // Challenge expired before completion
}

/**
 * Interface for MFA factor data
 */
export interface MfaFactorData {
  id: string;
  userId: string;
  type: MfaFactorType;
  name: string;
  secret?: string;
  credentialId?: string;
  phoneNumber?: string;
  email?: string;
  deviceToken?: string;
  metadata?: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
  lastUsedAt?: Date;
  verifiedAt?: Date;
  status: MfaFactorStatus;
}

/**
 * Interface for MFA challenge data
 */
export interface MfaChallengeData {
  id: string;
  factorId: string;
  challenge: string;
  response?: string;
  expiresAt: Date;
  createdAt: Date;
  completedAt?: Date;
  status: MfaChallengeStatus;
  attempts: number;
  metadata?: Record<string, any>;
}

/**
 * Interface for MFA verification result
 */
export interface MfaVerificationResult {
  success: boolean;
  factorId?: string;
  factorType?: MfaFactorType;
  message?: string;
  metadata?: Record<string, any>;
}

/**
 * Interface for MFA enrollment result
 */
export interface MfaEnrollmentResult {
  success: boolean;
  factorId?: string;
  factorType?: MfaFactorType;
  message?: string;
  activationData?: Record<string, any>;
  qrCode?: string;
  secret?: string;
  recoveryCodes?: string[];
}
