import { Injectable } from "@tsed/di";
import { recoveryConfig } from "../../../config/recovery.config";
import { RecoveryMethodStatus } from "../../../data/models/recovery-method.model";
import { auditLogRepository } from "../../../data/repositories/audit-log.repository";
import { recoveryMethodRepository } from "../../../data/repositories/recovery-method.repository";
import { recoveryRequestRepository } from "../../../data/repositories/recovery-request.repository";
import { userProfileRepository } from "../../../data/repositories/user-profile.repository";
import { userRepository } from "../../../data/repositories/user.repository";
import { logger } from "../../../infrastructure/logging/logger";
import { BadRequestError, NotFoundError } from "../../../utils/error-handling";
import {
  BaseRecoveryMethod,
  RecoveryInitiationResult,
  RecoveryMethodType,
  RecoveryVerificationResult,
} from "../recovery-method";

/**
 * Trusted contact interface
 */
interface TrustedContact {
  id: string;
  userId: string | null;
  email: string;
  name: string;
  relationship?: string;
  addedAt: string;
  verifiedAt?: string;
}

/**
 * Trusted contact recovery service
 * Implements trusted contact-based account recovery
 */
@Injectable()
export class TrustedContactService extends BaseRecoveryMethod {
  /**
   * The type of recovery method
   */
  protected readonly type = RecoveryMethodType.TRUSTED_CONTACTS;

  /**
   * In-memory code storage (replace with Redis in production)
   * Maps requestId to verification data
   */
  private verificationCodes: Map<
    string,
    { code: string; userId: string; attempts: number; expiresAt: Date; contacts: TrustedContact[] }
  > = new Map();

  /**
   * Check if trusted contact recovery is available for a user
   * @param userId User ID
   * @returns True if trusted contact recovery is available
   */
  async isAvailableForUser(userId: string): Promise<boolean> {
    try {
      // Get user profile
      const profile = await userProfileRepository.findByUserId(userId);
      if (!profile || !profile.metadata) {
        return false;
      }

      // Check if trusted contacts are set up
      const metadata = profile.metadata as Record<string, any>;
      if (!metadata['trustedContacts'] || !Array.isArray(metadata['trustedContacts'])) {
        return false;
      }

      // Check if there are enough trusted contacts
      return metadata['trustedContacts'].length >= recoveryConfig.trustedContacts.minContactsForRecovery;
    } catch (error) {
      logger.error("Failed to check if trusted contact recovery is available", { error, userId });
      return false;
    }
  }

  /**
   * Register trusted contact recovery for a user
   * @param userId User ID
   * @param name Name for the recovery method
   * @param data Additional method-specific data
   * @returns ID of the created recovery method
   */
  async register(userId: string, name: string, data: Record<string, any> = {}): Promise<string> {
    try {
      // Check if user exists
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError("User not found");
      }

      // Check if trusted contacts are provided
      const contacts = data['contacts'];
      if (!contacts || !Array.isArray(contacts) || contacts.length < 1) {
        throw new BadRequestError("At least one trusted contact is required");
      }

      // Validate contacts
      for (const contact of contacts) {
        if (!contact.email || typeof contact.email !== "string" || !this.isValidEmail(contact.email)) {
          throw new BadRequestError("All contacts must have valid email addresses");
        }

        if (!contact.name || typeof contact.name !== "string" || contact.name.trim().length === 0) {
          throw new BadRequestError("All contacts must have names");
        }
      }

      // Get or create user profile
      let profile = await userProfileRepository.findByUserId(userId);
      if (!profile) {
        profile = await userProfileRepository.create({
          userId,
          metadata: {},
        });
      }

      // Create trusted contacts
      const trustedContacts: TrustedContact[] = contacts.map((contact: any, index: number) => ({
        id: `tc-${Date.now()}-${index}`,
        userId: contact.userId || null,
        email: contact.email.trim(),
        name: contact.name.trim(),
        relationship: contact.relationship || null,
        addedAt: new Date().toISOString(),
      }));

      // Update profile metadata
      const metadata = (profile.metadata as Record<string, any>) || {};
      metadata['trustedContacts'] = trustedContacts;

      // Update profile
      await userProfileRepository.updateByUserId(userId, {
        metadata,
      } as any);

      // Create recovery method
      const method = await recoveryMethodRepository.create({
        userId,
        type: RecoveryMethodType.TRUSTED_CONTACTS,
        name: name || "Trusted Contacts",
        status: RecoveryMethodStatus.ACTIVE,
        metadata: {
          contactCount: trustedContacts.length,
        },
      });

      // Log the registration
      await auditLogRepository.create({
        userId,
        action: "RECOVERY_METHOD_REGISTERED",
        entityType: "RECOVERY_METHOD",
        entityId: method.id,
        metadata: {
          type: RecoveryMethodType.TRUSTED_CONTACTS,
          name: method.name,
          contactCount: trustedContacts.length,
        },
      });

      return method.id;
    } catch (error) {
      logger.error("Failed to register trusted contact recovery", { error, userId });
      throw error;
    }
  }

  /**
   * Initiate trusted contact recovery
   * @param userId User ID
   * @param requestId Recovery request ID
   * @returns Recovery data
   */
  async initiateRecovery(
    userId: string,
    requestId: string
  ): Promise<RecoveryInitiationResult> {
    try {
      // Get user
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError("User not found");
      }

      // Get user profile
      const profile = await userProfileRepository.findByUserId(userId);
      if (!profile || !profile.metadata) {
        throw new NotFoundError("User profile not found");
      }

      // Get trusted contacts
      const metadata = profile.metadata as Record<string, any>;
      if (!metadata['trustedContacts'] || !Array.isArray(metadata['trustedContacts'])) {
        throw new BadRequestError("Trusted contacts not set up");
      }

      const contacts = metadata['trustedContacts'] as TrustedContact[];
      if (contacts.length < recoveryConfig.trustedContacts.minContactsForRecovery) {
        throw new BadRequestError(
          `At least ${recoveryConfig.trustedContacts.minContactsForRecovery} trusted contact is required`
        );
      }

      // Get recovery request
      const request = await recoveryRequestRepository.findById(requestId);
      if (!request) {
        throw new NotFoundError("Recovery request not found");
      }

      // Generate a recovery code
      const code = this.generateRecoveryCode();

      // Store the code with expiration
      const expiresAt = new Date(Date.now() + recoveryConfig.trustedContacts.codeExpiration * 1000);
      this.verificationCodes.set(requestId, {
        code,
        userId,
        attempts: 0,
        expiresAt,
        contacts,
      });

      // In a real implementation, send the code to the trusted contacts
      // For now, we'll just log it
      logger.info("Trusted contact recovery code", {
        userId,
        contacts: contacts.map(c => ({ email: c.email, name: c.name })),
        code,
        expiresAt,
      });

      // Update request metadata
      await recoveryRequestRepository.update(requestId, {
        metadata: {
          ...request.metadata,
          methodType: RecoveryMethodType.TRUSTED_CONTACTS,
          contactCount: contacts.length,
          expiresAt: expiresAt.toISOString(),
        },
      });

      // Log the recovery initiation
      await auditLogRepository.create({
        userId,
        action: "TRUSTED_CONTACT_RECOVERY_INITIATED",
        entityType: "RECOVERY_REQUEST",
        entityId: requestId,
        metadata: {
          contactCount: contacts.length,
          expiresAt: expiresAt.toISOString(),
        },
      });

      // Return recovery data
      return {
        metadata: {
          contacts,
          expiresAt,
        },
        clientData: {
          contacts: contacts.map(c => ({
            name: c.name,
            email: this.maskEmail(c.email),
          })),
          message: "A recovery code has been sent to your trusted contacts",
          expiresAt,
        },
      };
    } catch (error) {
      logger.error("Failed to initiate trusted contact recovery", { error, userId, requestId });
      throw error;
    }
  }

  /**
   * Verify trusted contact recovery
   * @param requestId Recovery request ID
   * @param verificationData Verification data
   * @returns Verification result
   */
  async verifyRecovery(
    requestId: string,
    verificationData: Record<string, any>
  ): Promise<RecoveryVerificationResult> {
    try {
      // Get verification code data
      const storedData = this.verificationCodes.get(requestId);
      if (!storedData) {
        return {
          success: false,
          message: "Invalid or expired recovery code",
        };
      }

      // Get the code from verification data
      const { code } = verificationData;
      if (!code) {
        return {
          success: false,
          message: "Recovery code is required",
        };
      }

      // Check if code is expired
      if (storedData.expiresAt < new Date()) {
        this.verificationCodes.delete(requestId);
        return {
          success: false,
          message: "Recovery code has expired",
        };
      }

      // Increment attempts
      storedData.attempts += 1;

      // Check if max attempts reached (using a reasonable default)
      const maxAttempts = 5;
      if (storedData.attempts > maxAttempts) {
        this.verificationCodes.delete(requestId);
        return {
          success: false,
          message: "Maximum verification attempts reached",
        };
      }

      // Verify the code
      if (storedData.code !== code) {
        return {
          success: false,
          message: `Invalid recovery code. ${maxAttempts - storedData.attempts} attempts remaining`,
        };
      }

      // Remove the code
      this.verificationCodes.delete(requestId);

      // Log successful verification
      await auditLogRepository.create({
        userId: storedData.userId,
        action: "TRUSTED_CONTACT_RECOVERY_VERIFIED",
        entityType: "RECOVERY_REQUEST",
        entityId: requestId,
      });

      return {
        success: true,
        message: "Trusted contact verification successful",
      };
    } catch (error) {
      logger.error("Failed to verify trusted contact recovery", { error, requestId });
      return {
        success: false,
        message: "An error occurred during verification",
      };
    }
  }

  /**
   * Add a trusted contact for a user
   * @param userId User ID
   * @param contactEmail Contact email
   * @param contactName Contact name
   * @param relationship Relationship to the user
   * @returns Result of the operation
   */
  async addTrustedContact(
    userId: string,
    contactEmail: string,
    contactName: string,
    relationship?: string
  ): Promise<{ success: boolean; contactId: string }> {
    try {
      // Check if user exists
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError("User not found");
      }

      // Validate email
      if (!this.isValidEmail(contactEmail)) {
        throw new BadRequestError("Invalid email address");
      }

      // Validate name
      if (!contactName || contactName.trim().length === 0) {
        throw new BadRequestError("Contact name is required");
      }

      // Get or create user profile
      let profile = await userProfileRepository.findByUserId(userId);
      if (!profile) {
        profile = await userProfileRepository.create({
          userId,
          metadata: {},
        });
      }

      // Get existing trusted contacts
      const metadata = (profile.metadata as Record<string, any>) || {};
      const trustedContacts: TrustedContact[] = metadata['trustedContacts'] || [];

      // Check if contact already exists
      const existingContact = trustedContacts.find(c => c.email.toLowerCase() === contactEmail.toLowerCase());
      if (existingContact) {
        throw new BadRequestError("Contact is already a trusted contact");
      }

      // Check if maximum contacts reached
      if (trustedContacts.length >= recoveryConfig.trustedContacts.maxContacts) {
        throw new BadRequestError(
          `Maximum number of trusted contacts (${recoveryConfig.trustedContacts.maxContacts}) reached`
        );
      }

      // Create new trusted contact
      const contactId = `tc-${Date.now()}-${trustedContacts.length}`;
      const newContact: TrustedContact = {
        id: contactId,
        userId: null,
        email: contactEmail.trim(),
        name: contactName.trim(),
        relationship: relationship?.trim(),
        addedAt: new Date().toISOString(),
      };

      // Add to trusted contacts
      trustedContacts.push(newContact);
      metadata['trustedContacts'] = trustedContacts;

      // Update profile
      await userProfileRepository.updateByUserId(userId, {
        metadata,
      } as any);

      // Log the addition
      await auditLogRepository.create({
        userId,
        action: "TRUSTED_CONTACT_ADDED",
        metadata: {
          contactId,
          contactEmail: newContact.email,
          contactName: newContact.name,
        },
      });

      return {
        success: true,
        contactId,
      };
    } catch (error) {
      logger.error("Failed to add trusted contact", { error, userId, contactEmail });
      throw error;
    }
  }

  /**
   * Remove a trusted contact for a user
   * @param userId User ID
   * @param contactId Contact ID
   * @returns Result of the operation
   */
  async removeTrustedContact(userId: string, contactId: string): Promise<{ success: boolean }> {
    try {
      // Check if user exists
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError("User not found");
      }

      // Get user profile
      const profile = await userProfileRepository.findByUserId(userId);
      if (!profile || !profile.metadata) {
        throw new NotFoundError("User profile not found");
      }

      // Get trusted contacts
      const metadata = profile.metadata as Record<string, any>;
      const trustedContacts: TrustedContact[] = metadata['trustedContacts'] || [];

      // Find contact
      const contactIndex = trustedContacts.findIndex(c => c.id === contactId);
      if (contactIndex === -1) {
        throw new NotFoundError("Trusted contact not found");
      }

      // Remove contact
      trustedContacts.splice(contactIndex, 1);
      metadata['trustedContacts'] = trustedContacts;

      // Update profile
      await userProfileRepository.updateByUserId(userId, {
        metadata,
      } as any);

      // Log the removal
      await auditLogRepository.create({
        userId,
        action: "TRUSTED_CONTACT_REMOVED",
        metadata: {
          contactId,
        },
      });

      return {
        success: true,
      };
    } catch (error) {
      logger.error("Failed to remove trusted contact", { error, userId, contactId });
      throw error;
    }
  }

  /**
   * Generate a random recovery code
   * @returns Recovery code
   */
  private generateRecoveryCode(): string {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Omitting similar-looking characters
    let code = "";
    for (let i = 0; i < recoveryConfig.trustedContacts.codeLength; i++) {
      code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
  }

  /**
   * Mask an email address for privacy
   * @param email Email address
   * @returns Masked email address
   */
  private maskEmail(email: string): string {
    const parts = email.split("@");
    if (parts.length !== 2) {
      return email; // Return original if not a valid email format
    }
    
    const username = parts[0] || "";
    const domain = parts[1] || "";
    
    if (!username || !domain) {
      return email; // Return original if username or domain is empty
    }
    
    const maskedUsername =
      username.length > 2
        ? `${username.substring(0, 2)}${"*".repeat(username.length - 2)}`
        : username;
    
    return `${maskedUsername}@${domain}`;
  }

  /**
   * Validate an email address
   * @param email Email address to validate
   * @returns True if the email is valid
   */
  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
}

// Export a singleton instance
export const trustedContactService = new TrustedContactService();
