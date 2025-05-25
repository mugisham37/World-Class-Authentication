/**
 * Credential type enum
 * Represents the type of credential in the system
 */
export enum CredentialType {
  PASSWORD = 'PASSWORD',
  API_KEY = 'API_KEY',
  OAUTH = 'OAUTH',
}

/**
 * Credential model interface
 * Represents a user credential in the system
 */
export interface Credential {
  id: string;
  userId: string;
  type: CredentialType;
  identifier: string;
  secret: string;
  algorithm?: string | null;
  salt?: string | null;
  iterations?: number | null;
  createdAt: Date;
  updatedAt: Date;
  lastUsedAt?: Date | null;
  expiresAt?: Date | null;
}

/**
 * Create credential data interface
 * Represents the data needed to create a new credential
 */
export interface CreateCredentialData {
  userId: string;
  type: CredentialType;
  identifier: string;
  secret: string;
  algorithm?: string;
  salt?: string;
  iterations?: number;
  expiresAt?: Date;
}

/**
 * Update credential data interface
 * Represents the data needed to update an existing credential
 */
export interface UpdateCredentialData {
  secret?: string;
  algorithm?: string;
  salt?: string;
  iterations?: number;
  lastUsedAt?: Date;
  expiresAt?: Date;
}

/**
 * Credential filter options interface
 * Represents the options for filtering credentials
 */
export interface CredentialFilterOptions {
  id?: string;
  userId?: string;
  type?: CredentialType;
  identifier?: string;
  createdAtBefore?: Date;
  createdAtAfter?: Date;
  updatedAtBefore?: Date;
  updatedAtAfter?: Date;
  lastUsedAtBefore?: Date;
  lastUsedAtAfter?: Date;
  expiresAtBefore?: Date;
  expiresAtAfter?: Date;
}
