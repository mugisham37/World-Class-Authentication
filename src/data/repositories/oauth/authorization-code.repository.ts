/**
 * OAuth Authorization Code Repository Interface
 * Defines methods for managing OAuth authorization codes
 */
export interface AuthorizationCodeRepository {
  /**
   * Find an authorization code by its value
   * @param code Authorization code value
   * @returns Authorization code object or null if not found
   */
  findByCode(code: string): Promise<any | null>;

  /**
   * Create a new authorization code
   * @param code Authorization code data
   * @returns Created authorization code
   */
  create(code: any): Promise<any>;

  /**
   * Mark an authorization code as used
   * @param code Authorization code value
   * @returns True if marked as used, false otherwise
   */
  markAsUsed(code: string): Promise<boolean>;

  /**
   * Find authorization codes by user ID
   * @param userId User ID
   * @returns Array of authorization codes
   */
  findByUserId(userId: string): Promise<any[]>;

  /**
   * Find authorization codes by client ID
   * @param clientId Client ID
   * @returns Array of authorization codes
   */
  findByClientId(clientId: string): Promise<any[]>;

  /**
   * Delete expired authorization codes
   * @returns Number of deleted authorization codes
   */
  deleteExpired(): Promise<number>;
}
