/**
 * OAuth Token Repository Interface
 * Defines methods for managing OAuth tokens
 */
export interface TokenRepository {
  /**
   * Find a token by its value and type
   * @param value Token value
   * @param type Token type (access_token, refresh_token, etc.)
   * @returns Token object or null if not found
   */
  findByValue(value: string, type: string): Promise<any | null>;

  /**
   * Create a new token
   * @param token Token data
   * @returns Created token
   */
  create(token: any): Promise<any>;

  /**
   * Revoke a token
   * @param id Token ID
   * @returns True if revoked, false otherwise
   */
  revoke(id: string): Promise<boolean>;

  /**
   * Find tokens by user ID
   * @param userId User ID
   * @returns Array of tokens
   */
  findByUserId(userId: string): Promise<any[]>;

  /**
   * Find tokens by client ID
   * @param clientId Client ID
   * @returns Array of tokens
   */
  findByClientId(clientId: string): Promise<any[]>;

  /**
   * Delete expired tokens
   * @returns Number of deleted tokens
   */
  deleteExpired(): Promise<number>;
}
