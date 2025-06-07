import type { Request, Response } from 'express';
import { trustedContactService } from '../../core/recovery/methods/trusted-contact.service';
import { AuthenticationError, BadRequestError } from '../../utils/error-handling';
import { sendCreatedResponse, sendOkResponse } from '../responses';
import { BaseController } from './base.controller';

/**
 * Trusted Contact controller
 * Handles trusted contact management for account recovery
 */
export class TrustedContactController extends BaseController {
  /**
   * Get trusted contacts for a user
   * @route GET /trusted-contacts
   */
  getUserContacts = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    // In a real implementation, we would retrieve the user's trusted contacts
    // For now, we'll return a placeholder response
    sendOkResponse(res, 'Trusted contacts retrieved successfully', {
      contacts: [
        {
          id: '1',
          name: 'John Doe',
          email: 'j***@example.com',
          relationship: 'Friend',
          addedAt: new Date().toISOString(),
        },
        {
          id: '2',
          name: 'Jane Smith',
          email: 'j***@example.com',
          relationship: 'Family',
          addedAt: new Date().toISOString(),
        },
      ],
    });
  });

  /**
   * Add a trusted contact
   * @route POST /trusted-contacts
   */
  addTrustedContact = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    const userId = req.user.id;
    const { name, email, relationship } = req.body;

    // Validate required fields
    if (!name) {
      throw new BadRequestError('Contact name is required', 'NAME_REQUIRED');
    }

    if (!email) {
      throw new BadRequestError('Contact email is required', 'EMAIL_REQUIRED');
    }

    // Add trusted contact
    const result = await trustedContactService.addTrustedContact(userId, email, name, relationship);

    sendCreatedResponse(res, 'Trusted contact added successfully', {
      success: result.success,
      contactId: result.contactId,
    });
  });

  /**
   * Remove a trusted contact
   * @route DELETE /trusted-contacts/:contactId
   */
  removeTrustedContact = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    const userId = req.user.id;
    const { contactId } = req.params;

    // Validate contact ID
    if (!contactId) {
      throw new BadRequestError('Contact ID is required', 'CONTACT_ID_REQUIRED');
    }

    // Remove trusted contact
    const result = await trustedContactService.removeTrustedContact(userId, contactId);

    sendOkResponse(res, 'Trusted contact removed successfully', {
      success: result.success,
    });
  });

  /**
   * Register trusted contacts as a recovery method
   * @route POST /trusted-contacts/register-recovery
   */
  registerRecoveryMethod = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    const userId = req.user.id;
    const { name, contacts } = req.body;

    // Validate contacts
    if (!contacts || !Array.isArray(contacts) || contacts.length === 0) {
      throw new BadRequestError('At least one contact is required', 'CONTACTS_REQUIRED');
    }

    // Register trusted contacts as a recovery method
    const methodId = await trustedContactService.register(
      userId,
      name || 'Trusted Contacts Recovery',
      { contacts }
    );

    sendCreatedResponse(res, 'Trusted contacts registered as recovery method', {
      methodId,
      contactCount: contacts.length,
    });
  });

  /**
   * Initiate recovery using trusted contacts
   * @route POST /trusted-contacts/initiate-recovery
   */
  initiateRecovery = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { userId, requestId } = req.body;

    // Validate required fields
    if (!userId) {
      throw new BadRequestError('User ID is required', 'USER_ID_REQUIRED');
    }

    if (!requestId) {
      throw new BadRequestError('Request ID is required', 'REQUEST_ID_REQUIRED');
    }

    // Initiate recovery
    const result = await trustedContactService.initiateRecovery(userId, requestId);

    sendOkResponse(res, 'Recovery initiated with trusted contacts', {
      contacts: result.clientData['contacts'],
      message: result.clientData['message'],
      expiresAt: result.clientData['expiresAt'],
    });
  });

  /**
   * Verify recovery code from trusted contacts
   * @route POST /trusted-contacts/verify-recovery
   */
  verifyRecovery = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { requestId, code } = req.body;

    // Validate required fields
    if (!requestId) {
      throw new BadRequestError('Request ID is required', 'REQUEST_ID_REQUIRED');
    }

    if (!code) {
      throw new BadRequestError('Recovery code is required', 'CODE_REQUIRED');
    }

    // Verify recovery code
    const result = await trustedContactService.verifyRecovery(requestId, { code });

    sendOkResponse(res, result.message || 'Verification processed', {
      success: result.success,
    });
  });

  /**
   * Check if trusted contact recovery is available for a user
   * @route GET /trusted-contacts/availability/:userId
   */
  checkAvailability = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { userId } = req.params;

    // Validate user ID
    if (!userId) {
      throw new BadRequestError('User ID is required', 'USER_ID_REQUIRED');
    }

    // Check availability
    const isAvailable = await trustedContactService.isAvailableForUser(userId);

    sendOkResponse(res, 'Trusted contact recovery availability checked', {
      isAvailable,
    });
  });
}

// Create instance
export const trustedContactController = new TrustedContactController();
