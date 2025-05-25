/**
 * Recovery method type enum
 * Represents the type of recovery method in the system
 */
export enum RecoveryMethodType {
  EMAIL = 'EMAIL',
  SECURITY_QUESTIONS = 'SECURITY_QUESTIONS',
  TRUSTED_CONTACTS = 'TRUSTED_CONTACTS',
  RECOVERY_CODES = 'RECOVERY_CODES',
  ADMIN_RECOVERY = 'ADMIN_RECOVERY',
}

/**
 * Recovery method status enum
 * Represents the status of a recovery method in the system
 */
export enum RecoveryMethodStatus {
  ACTIVE = 'ACTIVE',
  DISABLED = 'DISABLED',
  PENDING = 'PENDING',
}

/**
 * Recovery method model interface
 * Represents a recovery method in the system
 */
export interface RecoveryMethod {
  id: string;
  userId: string;
  type: RecoveryMethodType;
  name: string;
  status: RecoveryMethodStatus;
  createdAt: Date;
  updatedAt: Date;
  lastUsedAt?: Date | null;
  metadata?: Record<string, any> | null;
}

/**
 * Create recovery method data interface
 * Represents the data needed to create a new recovery method
 */
export interface CreateRecoveryMethodData {
  userId: string;
  type: RecoveryMethodType;
  name: string;
  status?: RecoveryMethodStatus;
  metadata?: Record<string, any>;
}

/**
 * Update recovery method data interface
 * Represents the data needed to update an existing recovery method
 */
export interface UpdateRecoveryMethodData {
  name?: string;
  status?: RecoveryMethodStatus;
  lastUsedAt?: Date;
  metadata?: Record<string, any>;
}

/**
 * Recovery method filter options interface
 * Represents the options for filtering recovery methods
 */
export interface RecoveryMethodFilterOptions {
  id?: string;
  userId?: string;
  type?: RecoveryMethodType;
  status?: RecoveryMethodStatus;
  createdAtBefore?: Date;
  createdAtAfter?: Date;
  updatedAtBefore?: Date;
  updatedAtAfter?: Date;
  lastUsedAtBefore?: Date;
  lastUsedAtAfter?: Date;
}
