import type { Request, Response } from 'express';
import { BaseController } from './base.controller';
import { sendOkResponse, sendCreatedResponse } from '../responses';
import { AuthenticationError, BadRequestError } from '../../utils/error-handling';
import { logger } from '../../infrastructure/logging/logger';
import { AuthUser } from './types/auth.types';

/**
 * Type guard to check if a user object has the required properties
 * @param user - The user object to check
 * @returns boolean indicating if the user has the required properties
 */
function isValidUser(user: any): user is AuthUser {
  return user && typeof user.id === 'string';
}

/**
 * Compliance controller
 * Handles compliance-related operations such as GDPR requests
 */
export class ComplianceController extends BaseController {
  /**
   * Submit a data subject request (DSR)
   * @route POST /compliance/data-requests
   */
  submitDataRequest = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    try {
      const { type, email, firstName, lastName, reason, proofOfIdentity } = req.body;

      // Validate request
      if (!type) {
        throw new BadRequestError('Request type is required', 'TYPE_REQUIRED');
      }

      if (!email) {
        throw new BadRequestError('Email is required', 'EMAIL_REQUIRED');
      }

      // In a real implementation, this would create a data subject request
      // For now, we'll just log the request
      logger.info('Data subject request submitted', {
        type,
        email,
        firstName,
        lastName,
        reason,
        hasProofOfIdentity: !!proofOfIdentity,
      });

      // Generate a request ID
      const requestId = `dsr_${Date.now()}_${Math.floor(Math.random() * 1000)}`;

      sendCreatedResponse(res, 'Data subject request submitted successfully', {
        requestId,
        status: 'PENDING',
        submittedAt: new Date(),
        estimatedCompletionDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      });
    } catch (error) {
      logger.error('Error submitting data subject request', { error });
      throw error;
    }
  });

  /**
   * Get data subject request status
   * @route GET /compliance/data-requests/:id
   */
  getDataRequestStatus = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;

      // In a real implementation, this would query the database
      // For now, we'll just return mock data
      const request = {
        id,
        type: 'DATA_ACCESS',
        status: 'PROCESSING',
        submittedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000), // 5 days ago
        estimatedCompletionDate: new Date(Date.now() + 25 * 24 * 60 * 60 * 1000), // 25 days from now
        lastUpdatedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000), // 2 days ago
      };

      sendOkResponse(res, 'Data subject request status retrieved successfully', request);
    } catch (error) {
      logger.error('Error getting data subject request status', {
        error,
        requestId: req.params['id'],
      });
      throw error;
    }
  });

  /**
   * Get user's data subject requests
   * @route GET /compliance/data-requests
   */
  getUserDataRequests = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    try {
      // In a real implementation, this would query the database
      // For now, we'll just return mock data
      const requests = [
        {
          id: 'dsr_1',
          type: 'DATA_ACCESS',
          status: 'COMPLETED',
          submittedAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000), // 60 days ago
          completedAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 30 days ago
          downloadUrl: 'https://example.com/download/dsr_1',
        },
        {
          id: 'dsr_2',
          type: 'DATA_DELETION',
          status: 'PROCESSING',
          submittedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000), // 5 days ago
          estimatedCompletionDate: new Date(Date.now() + 25 * 24 * 60 * 60 * 1000), // 25 days from now
        },
      ];

      sendOkResponse(res, 'Data subject requests retrieved successfully', requests);
    } catch (error) {
      // Ensure user has id property before accessing it
      if (req.user && isValidUser(req.user)) {
        logger.error("Error getting user's data subject requests", { error, userId: req.user.id });
      } else {
        logger.error("Error getting user's data subject requests", { error, userId: 'unknown' });
      }
      throw error;
    }
  });

  /**
   * Cancel a data subject request
   * @route DELETE /compliance/data-requests/:id
   */
  cancelDataRequest = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    try {
      const { id } = req.params;

      // In a real implementation, this would update the database
      // For now, we'll just log the request
      // Ensure user has id property before accessing it
      if (req.user && isValidUser(req.user)) {
        logger.info('Data subject request cancelled', {
          requestId: id,
          userId: req.user.id,
        });
      } else {
        logger.info('Data subject request cancelled', {
          requestId: id,
          userId: 'unknown',
        });
      }

      sendOkResponse(res, 'Data subject request cancelled successfully');
    } catch (error) {
      logger.error('Error cancelling data subject request', {
        error,
        requestId: req.params['id'],
        userId: req.user && isValidUser(req.user) ? req.user.id : 'unknown',
      });
      throw error;
    }
  });

  /**
   * Get privacy policy
   * @route GET /compliance/policies/privacy
   */
  getPrivacyPolicy = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    try {
      // Get version parameter
      const version = req.query['version'] as string;

      // In a real implementation, this would query the database
      // For now, we'll just return mock data
      const policy = {
        title: 'Privacy Policy',
        version: version || '1.0',
        effectiveDate: new Date('2025-01-01'),
        lastUpdated: new Date('2025-01-01'),
        content:
          'This is a mock privacy policy. In a real implementation, this would contain the actual privacy policy text.',
        sections: [
          {
            title: 'Information We Collect',
            content: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.',
          },
          {
            title: 'How We Use Your Information',
            content: 'Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.',
          },
          {
            title: 'Your Rights',
            content: 'Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.',
          },
        ],
      };

      sendOkResponse(res, 'Privacy policy retrieved successfully', policy);
    } catch (error) {
      logger.error('Error getting privacy policy', { error, version: req.query['version'] });
      throw error;
    }
  });

  /**
   * Get terms of service
   * @route GET /compliance/policies/terms
   */
  getTermsOfService = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    try {
      // Get version parameter
      const version = req.query['version'] as string;

      // In a real implementation, this would query the database
      // For now, we'll just return mock data
      const terms = {
        title: 'Terms of Service',
        version: version || '1.0',
        effectiveDate: new Date('2025-01-01'),
        lastUpdated: new Date('2025-01-01'),
        content:
          'This is a mock terms of service. In a real implementation, this would contain the actual terms of service text.',
        sections: [
          {
            title: 'Acceptance of Terms',
            content: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.',
          },
          {
            title: 'User Responsibilities',
            content: 'Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.',
          },
          {
            title: 'Limitation of Liability',
            content: 'Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.',
          },
        ],
      };

      sendOkResponse(res, 'Terms of service retrieved successfully', terms);
    } catch (error) {
      logger.error('Error getting terms of service', { error, version: req.query['version'] });
      throw error;
    }
  });

  /**
   * Get cookie policy
   * @route GET /compliance/policies/cookies
   */
  getCookiePolicy = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    try {
      // Get version parameter
      const version = req.query['version'] as string;

      // In a real implementation, this would query the database
      // For now, we'll just return mock data
      const policy = {
        title: 'Cookie Policy',
        version: version || '1.0',
        effectiveDate: new Date('2025-01-01'),
        lastUpdated: new Date('2025-01-01'),
        content:
          'This is a mock cookie policy. In a real implementation, this would contain the actual cookie policy text.',
        sections: [
          {
            title: 'What Are Cookies',
            content: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.',
          },
          {
            title: 'How We Use Cookies',
            content: 'Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.',
          },
          {
            title: 'Managing Cookies',
            content: 'Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.',
          },
        ],
        cookieCategories: [
          {
            name: 'Essential',
            description:
              'These cookies are necessary for the website to function and cannot be switched off in our systems.',
            required: true,
          },
          {
            name: 'Performance',
            description:
              'These cookies allow us to count visits and traffic sources so we can measure and improve the performance of our site.',
            required: false,
          },
          {
            name: 'Functional',
            description:
              'These cookies enable the website to provide enhanced functionality and personalisation.',
            required: false,
          },
          {
            name: 'Targeting',
            description: 'These cookies may be set through our site by our advertising partners.',
            required: false,
          },
        ],
      };

      sendOkResponse(res, 'Cookie policy retrieved successfully', policy);
    } catch (error) {
      logger.error('Error getting cookie policy', { error, version: req.query['version'] });
      throw error;
    }
  });

  /**
   * Update user cookie preferences
   * @route PUT /compliance/cookie-preferences
   */
  updateCookiePreferences = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    try {
      const { preferences } = req.body;

      if (!preferences || typeof preferences !== 'object') {
        throw new BadRequestError('Valid preferences object is required', 'PREFERENCES_REQUIRED');
      }

      // In a real implementation, this would update the database
      // For now, we'll just log the preferences
      logger.info('Cookie preferences updated', {
        preferences,
        userId: req.user && isValidUser(req.user) ? req.user.id : 'anonymous',
        ip: req.ip,
      });

      // Set cookie preferences in a cookie
      res.cookie('cookie_preferences', JSON.stringify(preferences), {
        maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
        httpOnly: false, // Allow JavaScript access
        secure: process.env['NODE_ENV'] === 'production',
        sameSite: 'strict',
      });

      sendOkResponse(res, 'Cookie preferences updated successfully', { preferences });
    } catch (error) {
      logger.error('Error updating cookie preferences', {
        error,
        userId: req.user && isValidUser(req.user) ? req.user.id : 'anonymous',
      });
      throw error;
    }
  });

  /**
   * Get data processing records
   * @route GET /compliance/data-processing
   */
  getDataProcessingRecords = this.handleAsync(
    async (req: Request, res: Response): Promise<void> => {
      // Check if user is authenticated and has admin role
      if (!req.user) {
        throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
      }

      // In a real implementation, check if user has admin role
      // For now, we'll just assume they do

      try {
        // In a real implementation, this would query the database
        // For now, we'll just return mock data
        const records = [
          {
            id: 'proc_1',
            category: 'User Authentication',
            purpose: 'To authenticate users and maintain session security',
            dataCategories: ['Email', 'Password Hash', 'IP Address', 'Device Information'],
            legalBasis: 'Contract',
            retention: 'Account lifetime + 30 days',
            recipients: ['Internal IT', 'Cloud Service Provider'],
            crossBorderTransfers: false,
            securityMeasures: ['Encryption', 'Access Controls', 'Audit Logging'],
          },
          {
            id: 'proc_2',
            category: 'Analytics',
            purpose: 'To analyze user behavior and improve service',
            dataCategories: ['Usage Data', 'IP Address', 'Device Information'],
            legalBasis: 'Legitimate Interest',
            retention: '90 days',
            recipients: ['Analytics Provider', 'Internal Product Team'],
            crossBorderTransfers: true,
            transferCountries: ['United States'],
            securityMeasures: ['Anonymization', 'Encryption', 'Access Controls'],
          },
        ];

        sendOkResponse(res, 'Data processing records retrieved successfully', records);
      } catch (error) {
        // Ensure user has id property before accessing it
        if (req.user && isValidUser(req.user)) {
          logger.error('Error getting data processing records', { error, userId: req.user.id });
        } else {
          logger.error('Error getting data processing records', { error, userId: 'unknown' });
        }
        throw error;
      }
    }
  );
}

// Create instance
export const complianceController = new ComplianceController();
