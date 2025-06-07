import type { Request, Response } from 'express';
import { BaseController } from './base.controller';
import { sendOkResponse } from '../responses';
import { AuthenticationError, BadRequestError, NotFoundError } from '../../utils/error-handling';
import { logger } from '../../infrastructure/logging/logger';
import { UserService } from '../../core/user/user.service';

// Import the user service
// In a real application with proper DI, this would be injected
const userService = new UserService();

/**
 * User controller
 * Handles user profile management and settings
 */
export class UserController extends BaseController {
  /**
   * Get current user profile
   * @route GET /users/me
   */
  getCurrentUser = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    try {
      // Get user by ID
      const user = await userService.findById(req.user.id);

      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Remove sensitive information
      const sanitizedUser = {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        displayName: user.displayName,
        emailVerified: user.emailVerified,
        phoneNumber: user.phoneNumber,
        phoneVerified: user.phoneVerified,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        lastLoginAt: user.lastLoginAt,
        preferences: user.preferences,
      };

      sendOkResponse(res, 'User profile retrieved successfully', sanitizedUser);
    } catch (error) {
      logger.error('Error getting current user profile', { error, userId: req.user.id });
      throw error;
    }
  });

  /**
   * Update current user profile
   * @route PUT /users/me
   */
  updateCurrentUser = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    try {
      // Validate update data
      const { firstName, lastName, displayName, phoneNumber, preferences } = req.body;

      // In a real implementation, this would update the user
      // For now, we'll just get the user and pretend we updated it
      const user = await userService.findById(req.user.id);

      // Mock update (in a real implementation, this would be saved to the database)
      Object.assign(user, {
        firstName: firstName || user.firstName,
        lastName: lastName || user.lastName,
        displayName: displayName || user.displayName,
        phoneNumber: phoneNumber || user.phoneNumber,
        preferences: preferences || user.preferences,
      });

      // Remove sensitive information
      const sanitizedUser = {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        displayName: user.displayName,
        emailVerified: user.emailVerified,
        phoneNumber: user.phoneNumber,
        phoneVerified: user.phoneVerified,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        lastLoginAt: user.lastLoginAt,
        preferences: user.preferences,
      };

      sendOkResponse(res, 'User profile updated successfully', sanitizedUser);
    } catch (error) {
      logger.error('Error updating current user profile', { error, userId: req.user.id });
      throw error;
    }
  });

  /**
   * Update user email
   * @route PUT /users/me/email
   */
  updateEmail = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    try {
      const { email, password } = req.body;

      if (!email) {
        throw new BadRequestError('Email is required', 'EMAIL_REQUIRED');
      }

      if (!password) {
        throw new BadRequestError('Password is required', 'PASSWORD_REQUIRED');
      }

      // In a real implementation, this would update the email
      // For now, we'll just log the request
      logger.info('Email update requested', {
        userId: req.user.id,
        newEmail: email,
      });

      sendOkResponse(
        res,
        'Email update initiated. Please check your new email for verification instructions.'
      );
    } catch (error) {
      logger.error('Error updating user email', { error, userId: req.user.id });
      throw error;
    }
  });

  /**
   * Update user phone number
   * @route PUT /users/me/phone
   */
  updatePhoneNumber = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    try {
      const { phoneNumber } = req.body;

      if (!phoneNumber) {
        throw new BadRequestError('Phone number is required', 'PHONE_NUMBER_REQUIRED');
      }

      // In a real implementation, this would update the phone number
      // For now, we'll just log the request
      logger.info('Phone number update requested', {
        userId: req.user.id,
        phoneNumber,
      });

      sendOkResponse(res, 'Phone number update initiated. Please verify your new phone number.');
    } catch (error) {
      logger.error('Error updating user phone number', { error, userId: req.user.id });
      throw error;
    }
  });

  /**
   * Verify phone number with code
   * @route POST /users/me/phone/verify
   */
  verifyPhoneNumber = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    try {
      const { code } = req.body;

      if (!code) {
        throw new BadRequestError('Verification code is required', 'CODE_REQUIRED');
      }

      // In a real implementation, this would verify the phone number
      // For now, we'll just log the request
      logger.info('Phone number verification requested', {
        userId: req.user.id,
        code,
      });

      sendOkResponse(res, 'Phone number verified successfully');
    } catch (error) {
      logger.error('Error verifying user phone number', { error, userId: req.user.id });
      throw error;
    }
  });

  /**
   * Update user preferences
   * @route PUT /users/me/preferences
   */
  updatePreferences = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    try {
      const { preferences } = req.body;

      if (!preferences || typeof preferences !== 'object') {
        throw new BadRequestError('Valid preferences object is required', 'PREFERENCES_REQUIRED');
      }

      // In a real implementation, this would update the preferences
      // For now, we'll just return the preferences that were sent
      const updatedPreferences = preferences;

      sendOkResponse(res, 'User preferences updated successfully', {
        preferences: updatedPreferences,
      });
    } catch (error) {
      logger.error('Error updating user preferences', { error, userId: req.user.id });
      throw error;
    }
  });

  /**
   * Get user activity log
   * @route GET /users/me/activity
   */
  getActivityLog = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    try {
      // Get pagination parameters
      const page = parseInt(req.query['page'] as string) || 1;
      const limit = parseInt(req.query['limit'] as string) || 10;

      // In a real implementation, this would get the activity log
      // For now, we'll just return a mock activity log
      const activityLog = {
        items: Array.from({ length: limit }, (_, i) => ({
          id: `activity_${i}`,
          type: i % 2 === 0 ? 'login' : 'profile_update',
          timestamp: new Date(Date.now() - i * 86400000),
          ipAddress: '127.0.0.1',
          userAgent: 'Mozilla/5.0',
          metadata: {},
        })),
        pagination: {
          page,
          limit,
          totalItems: 100,
          totalPages: Math.ceil(100 / limit),
        },
      };

      sendOkResponse(res, 'User activity log retrieved successfully', activityLog);
    } catch (error) {
      logger.error('Error getting user activity log', { error, userId: req.user.id });
      throw error;
    }
  });

  /**
   * Request account deletion
   * @route POST /users/me/delete
   */
  requestAccountDeletion = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    try {
      const { password } = req.body;

      if (!password) {
        throw new BadRequestError('Password is required', 'PASSWORD_REQUIRED');
      }

      // In a real implementation, this would request account deletion
      // For now, we'll just log the request
      logger.info('Account deletion requested', {
        userId: req.user.id,
      });

      sendOkResponse(
        res,
        'Account deletion requested. You will receive further instructions via email.'
      );
    } catch (error) {
      logger.error('Error requesting account deletion', { error, userId: req.user.id });
      throw error;
    }
  });

  /**
   * Cancel account deletion request
   * @route POST /users/me/delete/cancel
   */
  cancelAccountDeletion = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    try {
      // In a real implementation, this would cancel account deletion
      // For now, we'll just log the request
      logger.info('Account deletion cancelled', {
        userId: req.user.id,
      });

      sendOkResponse(res, 'Account deletion request cancelled successfully');
    } catch (error) {
      logger.error('Error cancelling account deletion request', { error, userId: req.user.id });
      throw error;
    }
  });

  /**
   * Export user data
   * @route GET /users/me/export
   */
  exportUserData = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    try {
      // Get data format
      const format = (req.query['format'] as string) || 'json';

      // In a real implementation, this would export user data
      // For now, we'll just return a mock export
      const user = await userService.findById(req.user.id);
      const exportData =
        format === 'json'
          ? JSON.stringify({ user, exportDate: new Date() }, null, 2)
          : format === 'csv'
            ? 'id,email,username\n' + `${user.id},${user.email},${user.username}`
            : `<user><id>${user.id}</id><email>${user.email}</email><username>${user.username}</username></user>`;

      // Set appropriate content type
      if (format === 'json') {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', 'attachment; filename=user-data.json');
      } else if (format === 'csv') {
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=user-data.csv');
      } else if (format === 'xml') {
        res.setHeader('Content-Type', 'application/xml');
        res.setHeader('Content-Disposition', 'attachment; filename=user-data.xml');
      }

      // Send data
      res.status(200).send(exportData);
    } catch (error) {
      logger.error('Error exporting user data', { error, userId: req.user.id });
      throw error;
    }
  });
}

// Create instance
export const userController = new UserController();
