/**
 * Trusted contact status enum
 * Represents the status of a trusted contact in the system
 */
export enum TrustedContactStatus {
  PENDING = 'PENDING',
  ACTIVE = 'ACTIVE',
  REVOKED = 'REVOKED',
}

/**
 * Trusted contact model interface
 * Represents a trusted contact in the system
 */
export interface TrustedContact {
  id: string;
  userId: string;
  name: string;
  email: string;
  phone?: string | null;
  relationship?: string | null;
  status: TrustedContactStatus;
  createdAt: Date;
  updatedAt: Date;
  verifiedAt?: Date | null;
}

/**
 * Create trusted contact data interface
 * Represents the data needed to create a new trusted contact
 */
export interface CreateTrustedContactData {
  userId: string;
  name: string;
  email: string;
  phone?: string;
  relationship?: string;
  status?: TrustedContactStatus;
}

/**
 * Update trusted contact data interface
 * Represents the data needed to update an existing trusted contact
 */
export interface UpdateTrustedContactData {
  name?: string;
  email?: string;
  phone?: string | null;
  relationship?: string | null;
  status?: TrustedContactStatus;
  verifiedAt?: Date | null;
}

/**
 * Trusted contact filter options interface
 * Represents the options for filtering trusted contacts
 */
export interface TrustedContactFilterOptions {
  id?: string;
  userId?: string;
  email?: string;
  status?: TrustedContactStatus;
  createdAtBefore?: Date;
  createdAtAfter?: Date;
  updatedAtBefore?: Date;
  updatedAtAfter?: Date;
  verifiedAtBefore?: Date;
  verifiedAtAfter?: Date;
}
