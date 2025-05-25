/**
 * Password history model interface
 * Represents a password history entry in the system
 */
export interface PasswordHistory {
  id: string;
  userId: string;
  credentialId: string;
  passwordHash: string;
  createdAt: Date;
}

/**
 * Create password history data interface
 * Represents the data needed to create a new password history entry
 */
export interface CreatePasswordHistoryData {
  userId: string;
  credentialId: string;
  passwordHash: string;
}

/**
 * Password history filter options interface
 * Represents the options for filtering password history entries
 */
export interface PasswordHistoryFilterOptions {
  id?: string;
  userId?: string;
  credentialId?: string;
  createdAtBefore?: Date;
  createdAtAfter?: Date;
}
