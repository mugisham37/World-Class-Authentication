/**
 * MFA factor type enum
 * Represents the type of MFA factor in the system
 */
export enum MfaFactorType {
  TOTP = 'TOTP',
  WEBAUTHN = 'WEBAUTHN',
  SMS = 'SMS',
  EMAIL = 'EMAIL',
  RECOVERY_CODE = 'RECOVERY_CODE',
  PUSH_NOTIFICATION = 'PUSH_NOTIFICATION',
}

/**
 * MFA factor status enum
 * Represents the status of an MFA factor in the system
 */
export enum MfaFactorStatus {
  ACTIVE = 'ACTIVE',
  PENDING = 'PENDING',
  DISABLED = 'DISABLED',
  REVOKED = 'REVOKED',
}

/**
 * MFA factor model interface
 * Represents an MFA factor in the system
 */
export interface MfaFactor {
  id: string;
  userId: string;
  type: MfaFactorType;
  name: string;
  secret?: string | null;
  credentialId?: string | null;
  phoneNumber?: string | null;
  email?: string | null;
  deviceToken?: string | null;
  metadata?: Record<string, any> | null;
  createdAt: Date;
  updatedAt: Date;
  lastUsedAt?: Date | null;
  verifiedAt?: Date | null;
  status: MfaFactorStatus;
}

/**
 * Create MFA factor data interface
 * Represents the data needed to create a new MFA factor
 */
export interface CreateMfaFactorData {
  userId: string;
  type: MfaFactorType;
  name: string;
  secret?: string;
  credentialId?: string;
  phoneNumber?: string;
  email?: string;
  deviceToken?: string;
  metadata?: Record<string, any>;
  status?: MfaFactorStatus;
}

/**
 * Update MFA factor data interface
 * Represents the data needed to update an existing MFA factor
 */
export interface UpdateMfaFactorData {
  name?: string;
  secret?: string;
  phoneNumber?: string;
  email?: string;
  deviceToken?: string;
  metadata?: Record<string, any>;
  lastUsedAt?: Date;
  verifiedAt?: Date;
  status?: MfaFactorStatus;
}

/**
 * MFA factor filter options interface
 * Represents the options for filtering MFA factors
 */
export interface MfaFactorFilterOptions {
  id?: string;
  userId?: string;
  type?: MfaFactorType;
  status?: MfaFactorStatus;
  verifiedOnly?: boolean;
  createdAtBefore?: Date;
  createdAtAfter?: Date;
  updatedAtBefore?: Date;
  updatedAtAfter?: Date;
  lastUsedAtBefore?: Date;
  lastUsedAtAfter?: Date;
  verifiedAtBefore?: Date;
  verifiedAtAfter?: Date;
}
