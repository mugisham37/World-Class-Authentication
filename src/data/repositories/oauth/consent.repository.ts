/**
 * OAuth Consent Repository Interface
 * Defines methods for managing OAuth consent records
 */
export interface ConsentRepository {
  /**
   * Find a consent record by user ID and client ID
   * @param userId User ID
   * @param clientId Client ID
   * @returns Consent record or null if not found
   */
  findByUserAndClient(userId: string, clientId: string): Promise<any | null>;

  /**
   * Create a new consent record
   * @param consent Consent data
   * @returns Created consent record
   */
  create(consent: any): Promise<any>;

  /**
   * Update an existing consent record
   * @param id Consent record ID
   * @param data Consent data to update
   * @returns Updated consent record
   */
  update(id: string, data: any): Promise<any>;

  /**
   * Revoke a consent record
   * @param id Consent record ID
   * @returns True if revoked, false otherwise
   */
  revoke(id: string): Promise<boolean>;

  /**
   * Find consent records by user ID
   * @param userId User ID
   * @returns Array of consent records
   */
  findByUserId(userId: string): Promise<any[]>;

  /**
   * Find consent records by client ID
   * @param clientId Client ID
   * @returns Array of consent records
   */
  findByClientId(clientId: string): Promise<any[]>;

  /**
   * Delete expired consent records
   * @returns Number of deleted consent records
   */
  deleteExpired(): Promise<number>;
}
