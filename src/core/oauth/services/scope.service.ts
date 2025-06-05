import { Injectable } from '@tsed/di';
import { Scope, CreateScopeInput, UpdateScopeInput } from '../models/scope.model';
import { logger } from '../../../infrastructure/logging/logger';
import { NotFoundError } from '../../../utils/error-handling';

/**
 * Service for managing OAuth scopes
 */
@Injectable()
export class ScopeService {
  constructor() {
    // Initialize with default scopes
    this.initializeDefaultScopes();
  }

  // In-memory scope storage for demonstration
  private scopes: Map<string, Scope> = new Map();

  /**
   * Initialize default scopes
   */
  private initializeDefaultScopes(): void {
    // OpenID Connect scopes
    const openidScope: Scope = {
      id: 'openid',
      name: 'openid',
      displayName: 'OpenID',
      description: 'Authenticate using OpenID Connect',
      claims: ['sub'],
      isDefault: true,
      isOpenId: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const profileScope: Scope = {
      id: 'profile',
      name: 'profile',
      displayName: 'Profile',
      description: 'Access to user profile information',
      claims: [
        'name',
        'family_name',
        'given_name',
        'middle_name',
        'nickname',
        'preferred_username',
        'profile',
        'picture',
        'website',
        'gender',
        'birthdate',
        'zoneinfo',
        'locale',
        'updated_at',
      ],
      isDefault: true,
      isOpenId: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const emailScope: Scope = {
      id: 'email',
      name: 'email',
      displayName: 'Email',
      description: 'Access to user email address',
      claims: ['email', 'email_verified'],
      isDefault: true,
      isOpenId: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const addressScope: Scope = {
      id: 'address',
      name: 'address',
      displayName: 'Address',
      description: 'Access to user address information',
      claims: ['address'],
      isDefault: false,
      isOpenId: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const phoneScope: Scope = {
      id: 'phone',
      name: 'phone',
      displayName: 'Phone',
      description: 'Access to user phone number',
      claims: ['phone_number', 'phone_number_verified'],
      isDefault: false,
      isOpenId: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const offlineAccessScope: Scope = {
      id: 'offline_access',
      name: 'offline_access',
      displayName: 'Offline Access',
      description: 'Access to refresh tokens for offline access',
      claims: [],
      isDefault: false,
      isOpenId: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    // API scopes
    const apiReadScope: Scope = {
      id: 'api:read',
      name: 'api:read',
      displayName: 'API Read',
      description: 'Read access to API resources',
      claims: [],
      isDefault: false,
      isOpenId: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const apiWriteScope: Scope = {
      id: 'api:write',
      name: 'api:write',
      displayName: 'API Write',
      description: 'Write access to API resources',
      claims: [],
      isDefault: false,
      isOpenId: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    // Add scopes to the map
    this.scopes.set(openidScope.id, openidScope);
    this.scopes.set(profileScope.id, profileScope);
    this.scopes.set(emailScope.id, emailScope);
    this.scopes.set(addressScope.id, addressScope);
    this.scopes.set(phoneScope.id, phoneScope);
    this.scopes.set(offlineAccessScope.id, offlineAccessScope);
    this.scopes.set(apiReadScope.id, apiReadScope);
    this.scopes.set(apiWriteScope.id, apiWriteScope);
  }

  /**
   * Find scope by ID
   * @param id Scope ID
   * @returns Scope or null if not found
   */
  async findById(id: string): Promise<Scope | null> {
    try {
      // In a real implementation, this would query the database
      const scope = this.scopes.get(id);
      return scope || null;
    } catch (error) {
      logger.error('Error finding scope by ID', { error, id });
      return null;
    }
  }

  /**
   * Find scope by name
   * @param name Scope name
   * @returns Scope or null if not found
   */
  async findByName(name: string): Promise<Scope | null> {
    try {
      // In a real implementation, this would query the database
      for (const scope of this.scopes.values()) {
        if (scope.name === name) {
          return scope;
        }
      }
      return null;
    } catch (error) {
      logger.error('Error finding scope by name', { error, name });
      return null;
    }
  }

  /**
   * Find all scopes
   * @returns Array of scopes
   */
  async findAll(): Promise<Scope[]> {
    try {
      // In a real implementation, this would query the database
      return Array.from(this.scopes.values());
    } catch (error) {
      logger.error('Error finding all scopes', { error });
      return [];
    }
  }

  /**
   * Find default scopes
   * @returns Array of default scopes
   */
  async findDefaultScopes(): Promise<Scope[]> {
    try {
      // In a real implementation, this would query the database
      const defaultScopes: Scope[] = [];
      for (const scope of this.scopes.values()) {
        if (scope.isDefault) {
          defaultScopes.push(scope);
        }
      }
      return defaultScopes;
    } catch (error) {
      logger.error('Error finding default scopes', { error });
      return [];
    }
  }

  /**
   * Find OpenID Connect scopes
   * @returns Array of OpenID Connect scopes
   */
  async findOpenIdScopes(): Promise<Scope[]> {
    try {
      // In a real implementation, this would query the database
      const openIdScopes: Scope[] = [];
      for (const scope of this.scopes.values()) {
        if (scope.isOpenId) {
          openIdScopes.push(scope);
        }
      }
      return openIdScopes;
    } catch (error) {
      logger.error('Error finding OpenID Connect scopes', { error });
      return [];
    }
  }

  /**
   * Create a new scope
   * @param data Scope data
   * @returns Created scope
   */
  async create(data: CreateScopeInput): Promise<Scope> {
    try {
      // Check if scope with same name already exists
      const existingScope = await this.findByName(data.name);
      if (existingScope) {
        throw new Error(`Scope with name '${data.name}' already exists`);
      }

      // Generate scope ID
      const id = data.name;

      // Create scope
      const scope: Scope = {
        ...data,
        id,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      // In a real implementation, this would save to the database
      this.scopes.set(id, scope);

      return scope;
    } catch (error) {
      logger.error('Error creating scope', { error });
      throw error;
    }
  }

  /**
   * Validate scope update data
   * @param scope Current scope
   * @param update Update data
   */
  private validateScopeUpdate(scope: Scope, update: UpdateScopeInput): void {
    if (update.name === '') {
      throw new Error('Scope name cannot be empty');
    }
    if (update.displayName === '') {
      throw new Error('Scope display name cannot be empty');
    }
    if (update.claims && update.claims.length === 0 && scope.isOpenId) {
      throw new Error('OpenID scope must have at least one claim');
    }
  }

  /**
   * Update a scope
   * @param id Scope ID
   * @param data Scope data to update
   * @returns Updated scope
   */
  async update(id: string, data: UpdateScopeInput): Promise<Scope> {
    try {
      // Find scope
      const scope = await this.findById(id);
      if (!scope) {
        throw new NotFoundError('Scope not found');
      }

      // Validate update data
      this.validateScopeUpdate(scope, data);

      // Check if name is being changed and if new name already exists
      if (data.name && data.name !== scope.name) {
        const existingScope = await this.findByName(data.name);
        if (existingScope) {
          throw new Error(`Scope with name '${data.name}' already exists`);
        }
      }

      // Update scope with type safety by explicitly handling each property
      const updatedScope: Scope = {
        ...scope,
        name: data.name ?? scope.name,
        displayName: data.displayName ?? scope.displayName,
        description: data.description ?? scope.description,
        iconUrl: data.iconUrl ?? scope.iconUrl,
        claims: data.claims ?? scope.claims,
        isDefault: data.isDefault ?? scope.isDefault,
        isOpenId: data.isOpenId ?? scope.isOpenId,
        updatedAt: new Date(),
      };

      // In a real implementation, this would update the database
      this.scopes.set(id, updatedScope);

      return updatedScope;
    } catch (error) {
      logger.error('Error updating scope', { error, id });
      throw error;
    }
  }

  /**
   * Delete a scope
   * @param id Scope ID
   * @returns True if deleted
   */
  async delete(id: string): Promise<boolean> {
    try {
      // Find scope
      const scope = await this.findById(id);
      if (!scope) {
        throw new NotFoundError('Scope not found');
      }

      // In a real implementation, this would delete from the database
      this.scopes.delete(id);

      return true;
    } catch (error) {
      logger.error('Error deleting scope', { error, id });
      throw error;
    }
  }

  /**
   * Validate scopes
   * @param scopeNames Array of scope names
   * @returns Array of valid scope names
   */
  async validateScopes(scopeNames: string[]): Promise<string[]> {
    try {
      const validScopes: string[] = [];

      for (const name of scopeNames) {
        const scope = await this.findByName(name);
        if (scope) {
          validScopes.push(name);
        }
      }

      return validScopes;
    } catch (error) {
      logger.error('Error validating scopes', { error, scopeNames });
      return [];
    }
  }

  /**
   * Get claims for scopes
   * @param scopeNames Array of scope names
   * @returns Array of claim names
   */
  async getClaimsForScopes(scopeNames: string[]): Promise<string[]> {
    try {
      const claims = new Set<string>();

      for (const name of scopeNames) {
        const scope = await this.findByName(name);
        if (scope) {
          for (const claim of scope.claims) {
            claims.add(claim);
          }
        }
      }

      return Array.from(claims);
    } catch (error) {
      logger.error('Error getting claims for scopes', { error, scopeNames });
      return [];
    }
  }
}
