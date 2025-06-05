import { Injectable } from '@tsed/di';
import { v4 as uuidv4 } from 'uuid';
import { Consent, CreateConsentInput, UpdateConsentInput } from '../models/consent.model';
import { logger } from '../../../infrastructure/logging/logger';
import { EventEmitter } from '../../../infrastructure/events/event-emitter';
import { OAuthEvent } from '../oauth-events';
import { NotFoundError } from '../../../utils/error-handling';
import { oauthConfig } from '../oauth.config';

/**
 * Service for managing OAuth user consents
 */
@Injectable()
export class ConsentService {
  constructor(
    private eventEmitter: EventEmitter
    // In a real implementation, this would be injected from a repository
    // private consentRepository: ConsentRepository
  ) {}

  // In-memory consent storage for demonstration
  private consents: Map<string, Consent> = new Map();

  /**
   * Find consent by ID
   * @param id Consent ID
   * @returns Consent or null if not found
   */
  async findById(id: string): Promise<Consent | null> {
    try {
      // In a real implementation, this would query the database
      const consent = this.consents.get(id);
      return consent || null;
    } catch (error) {
      logger.error('Error finding consent by ID', { error, id });
      return null;
    }
  }

  /**
   * Find consent by user ID and client ID
   * @param userId User ID
   * @param clientId Client ID
   * @returns Consent or null if not found
   */
  async findByUserAndClient(userId: string, clientId: string): Promise<Consent | null> {
    try {
      // In a real implementation, this would query the database
      for (const consent of this.consents.values()) {
        if (consent.userId === userId && consent.clientId === clientId) {
          return consent;
        }
      }
      return null;
    } catch (error) {
      logger.error('Error finding consent by user and client', { error, userId, clientId });
      return null;
    }
  }

  /**
   * Find consents by user ID
   * @param userId User ID
   * @returns Array of consents
   */
  async findByUserId(userId: string): Promise<Consent[]> {
    try {
      // In a real implementation, this would query the database
      const userConsents: Consent[] = [];
      for (const consent of this.consents.values()) {
        if (consent.userId === userId) {
          userConsents.push(consent);
        }
      }
      return userConsents;
    } catch (error) {
      logger.error('Error finding consents by user ID', { error, userId });
      return [];
    }
  }

  /**
   * Find consents by client ID
   * @param clientId Client ID
   * @returns Array of consents
   */
  async findByClientId(clientId: string): Promise<Consent[]> {
    try {
      // In a real implementation, this would query the database
      const clientConsents: Consent[] = [];
      for (const consent of this.consents.values()) {
        if (consent.clientId === clientId) {
          clientConsents.push(consent);
        }
      }
      return clientConsents;
    } catch (error) {
      logger.error('Error finding consents by client ID', { error, clientId });
      return [];
    }
  }

  /**
   * Create a new consent
   * @param data Consent data
   * @returns Created consent
   */
  async create(data: CreateConsentInput): Promise<Consent> {
    try {
      // Check if consent already exists
      const existingConsent = await this.findByUserAndClient(data.userId, data.clientId);
      if (existingConsent) {
        // Update existing consent instead of creating a new one
        return this.update(existingConsent.id, {
          scopes: data.scopes,
          expiresAt: data.expiresAt,
        });
      }

      // Generate consent ID
      const id = uuidv4();

      // Set expiration date based on config if not provided
      const expiresAt =
        data.expiresAt || new Date(Date.now() + oauthConfig.consent.expiration * 1000);

      // Create consent
      const consent: Consent = {
        ...data,
        id,
        expiresAt,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      // In a real implementation, this would save to the database
      this.consents.set(id, consent);

      // Emit consent granted event
      this.eventEmitter.emit(OAuthEvent.CONSENT_GRANTED, {
        clientId: data.clientId,
        userId: data.userId,
        scope: data.scopes.join(' '),
        timestamp: new Date(),
      });

      return consent;
    } catch (error) {
      logger.error('Error creating consent', { error });
      throw error;
    }
  }

  /**
   * Update a consent
   * @param id Consent ID
   * @param data Consent data to update
   * @returns Updated consent
   */
  async update(id: string, data: UpdateConsentInput): Promise<Consent> {
    try {
      // Find consent
      const consent = await this.findById(id);
      if (!consent) {
        throw new NotFoundError('Consent not found');
      }

      // Update consent with type safety
      const updatedConsent: Consent = {
        ...consent,
        scopes: data.scopes ?? consent.scopes,
        expiresAt: data.expiresAt ?? consent.expiresAt,
        updatedAt: new Date(),
      };

      // In a real implementation, this would update the database
      this.consents.set(id, updatedConsent);

      // Emit consent updated event
      this.eventEmitter.emit(OAuthEvent.CONSENT_UPDATED, {
        clientId: updatedConsent.clientId,
        userId: updatedConsent.userId,
        scope: updatedConsent.scopes.join(' '),
        timestamp: new Date(),
      });

      return updatedConsent;
    } catch (error) {
      logger.error('Error updating consent', { error, id });
      throw error;
    }
  }

  /**
   * Delete a consent
   * @param id Consent ID
   * @returns True if deleted
   */
  async delete(id: string): Promise<boolean> {
    try {
      // Find consent
      const consent = await this.findById(id);
      if (!consent) {
        throw new NotFoundError('Consent not found');
      }

      // In a real implementation, this would delete from the database
      this.consents.delete(id);

      // Emit consent revoked event
      this.eventEmitter.emit(OAuthEvent.CONSENT_REVOKED, {
        clientId: consent.clientId,
        userId: consent.userId,
        timestamp: new Date(),
      });

      return true;
    } catch (error) {
      logger.error('Error deleting consent', { error, id });
      throw error;
    }
  }

  /**
   * Delete all consents for a user
   * @param userId User ID
   * @returns Number of consents deleted
   */
  async deleteAllForUser(userId: string): Promise<number> {
    try {
      // Find consents for user
      const userConsents = await this.findByUserId(userId);
      let count = 0;

      // Delete each consent
      for (const consent of userConsents) {
        await this.delete(consent.id);
        count++;
      }

      return count;
    } catch (error) {
      logger.error('Error deleting all consents for user', { error, userId });
      throw error;
    }
  }

  /**
   * Delete all consents for a client
   * @param clientId Client ID
   * @returns Number of consents deleted
   */
  async deleteAllForClient(clientId: string): Promise<number> {
    try {
      // Find consents for client
      const clientConsents = await this.findByClientId(clientId);
      let count = 0;

      // Delete each consent
      for (const consent of clientConsents) {
        await this.delete(consent.id);
        count++;
      }

      return count;
    } catch (error) {
      logger.error('Error deleting all consents for client', { error, clientId });
      throw error;
    }
  }

  /**
   * Check if user has consented to scopes for a client
   * @param userId User ID
   * @param clientId Client ID
   * @param scopes Scopes to check
   * @returns True if user has consented to all scopes
   */
  async hasUserConsented(userId: string, clientId: string, scopes: string[]): Promise<boolean> {
    try {
      // Find consent
      const consent = await this.findByUserAndClient(userId, clientId);
      if (!consent) {
        return false;
      }

      // Check if consent has expired
      if (consent.expiresAt < new Date()) {
        return false;
      }

      // Check if user has consented to all scopes
      return scopes.every(scope => consent.scopes.includes(scope));
    } catch (error) {
      logger.error('Error checking if user has consented', { error, userId, clientId, scopes });
      return false;
    }
  }

  /**
   * Clean up expired consents
   * @returns Number of consents cleaned up
   */
  async cleanupExpiredConsents(): Promise<number> {
    try {
      const now = new Date();
      let count = 0;

      // In a real implementation, this would be a database query
      for (const [id, consent] of this.consents.entries()) {
        if (consent.expiresAt < now) {
          this.consents.delete(id);
          count++;
        }
      }

      return count;
    } catch (error) {
      logger.error('Error cleaning up expired consents', { error });
      throw error;
    }
  }
}
