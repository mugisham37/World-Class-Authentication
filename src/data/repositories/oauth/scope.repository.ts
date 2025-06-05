/**
 * OAuth Scope Repository Interface
 * Defines methods for managing OAuth scopes
 */
export interface ScopeRepository {
  /**
   * Find a scope by its name
   * @param name Scope name
   * @returns Scope object or null if not found
   */
  findByName(name: string): Promise<any | null>;

  /**
   * Create a new scope
   * @param scope Scope data
   * @returns Created scope
   */
  create(scope: any): Promise<any>;

  /**
   * Update an existing scope
   * @param id Scope ID
   * @param data Scope data to update
   * @returns Updated scope
   */
  update(id: string, data: any): Promise<any>;

  /**
   * Delete a scope
   * @param id Scope ID
   * @returns True if deleted, false otherwise
   */
  delete(id: string): Promise<boolean>;

  /**
   * Find all scopes
   * @returns Array of all scopes
   */
  findAll(): Promise<any[]>;

  /**
   * Find scopes by criteria
   * @param criteria Search criteria
   * @returns Array of scopes matching criteria
   */
  findByCriteria(criteria: any): Promise<any[]>;

  /**
   * Validate a list of scope names
   * @param scopes Array of scope names to validate
   * @returns Array of valid scope objects
   */
  validateScopes(scopes: string[]): Promise<any[]>;
}
