import type { Request, Response, NextFunction } from 'express';
import { BaseController } from './base.controller';
import { sendOkResponse, sendCreatedResponse } from '../responses';
import { AuthenticationError, BadRequestError, NotFoundError } from '../../utils/error-handling';
import { logger } from '../../infrastructure/logging/logger';
import { accountRecoveryService } from '../../core/recovery/account-recovery.service';
import { RecoveryMethodType } from '../../core/recovery/recovery-method';

/**
 * Recovery controller
 * Handles account recovery and password reset operations
 */
export class RecoveryController extends BaseController {
  /**
   * Get all recovery methods for the authenticated user
   * @route GET /recovery/methods
   */
  getUserRecoveryMethods = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    const userId = req.user.id;
    const methods = await accountRecoveryService.getUserRecoveryMethods(userId);

    sendOkResponse(res, 'Recovery methods retrieved successfully', methods);
  });

  /**
   * Get available recovery methods for the authenticated user
   * @route GET /recovery/methods/available
   */
  getAvailableRecoveryMethods = this.handleAsync(
    async (req: Request, res: Response): Promise<void> => {
      // Check if user is authenticated
      if (!req.user) {
        throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
      }

      const userId = req.user.id;
      const methods = await accountRecoveryService.getAvailableRecoveryMethods(userId);

      sendOkResponse(res, 'Available recovery methods retrieved successfully', methods);
    }
  );

  /**
   * Register a new recovery method
   * @route POST /recovery/methods
   */
  registerRecoveryMethod = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    const userId = req.user.id;
    const { type, name, data } = req.body;

    // Validate required fields
    if (!type) {
      throw new BadRequestError('Recovery method type is required', 'TYPE_REQUIRED');
    }

    if (!name) {
      throw new BadRequestError('Recovery method name is required', 'NAME_REQUIRED');
    }

    // Validate method type
    if (!Object.values(RecoveryMethodType).includes(type)) {
      throw new BadRequestError(`Invalid recovery method type: ${type}`, 'INVALID_METHOD_TYPE');
    }

    const method = await accountRecoveryService.registerRecoveryMethod(userId, type, name, data);

    sendCreatedResponse(res, 'Recovery method registered successfully', method);
  });

  /**
   * Disable a recovery method
   * @route PUT /recovery/methods/:methodId/disable
   */
  disableRecoveryMethod = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    const userId = req.user.id;
    const { methodId } = req.params;

    // Validate method ID
    if (!methodId) {
      throw new BadRequestError('Method ID is required', 'METHOD_ID_REQUIRED');
    }

    const result = await accountRecoveryService.disableRecoveryMethod(userId, methodId);

    sendOkResponse(res, result.message, { success: result.success });
  });

  /**
   * Enable a previously disabled recovery method
   * @route PUT /recovery/methods/:methodId/enable
   */
  enableRecoveryMethod = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    const userId = req.user.id;
    const { methodId } = req.params;

    // Validate method ID
    if (!methodId) {
      throw new BadRequestError('Method ID is required', 'METHOD_ID_REQUIRED');
    }

    const result = await accountRecoveryService.enableRecoveryMethod(userId, methodId);

    sendOkResponse(res, result.message, { success: result.success });
  });

  /**
   * Initiate account recovery process
   * @route POST /recovery/initiate
   */
  initiateRecovery = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { email, methodType } = req.body;
    const context = {
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    };

    logger.info(`Initiating recovery for email: ${email} using method: ${methodType}`, {
      context,
      methodType,
    });

    // Validate required fields
    if (!email) {
      throw new BadRequestError('Email is required', 'EMAIL_REQUIRED');
    }

    if (!methodType) {
      throw new BadRequestError('Recovery method type is required', 'METHOD_TYPE_REQUIRED');
    }

    // Validate method type
    if (!Object.values(RecoveryMethodType).includes(methodType)) {
      throw new BadRequestError(
        `Invalid recovery method type: ${methodType}`,
        'INVALID_METHOD_TYPE'
      );
    }

    const result = await accountRecoveryService.initiateRecovery(email, methodType, context);

    // For security reasons, always return a success response
    // even if the email doesn't exist
    sendOkResponse(res, result.message || 'Recovery instructions sent if email exists', {
      requestId: result.requestId,
      success: result.success,
    });
  });

  /**
   * Verify recovery challenge
   * @route POST /recovery/verify
   */
  verifyRecoveryChallenge = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { requestId, verificationData } = req.body;

    // Validate required fields
    if (!requestId) {
      throw new BadRequestError('Request ID is required', 'REQUEST_ID_REQUIRED');
    }

    if (!verificationData) {
      throw new BadRequestError('Verification data is required', 'VERIFICATION_DATA_REQUIRED');
    }

    logger.info(`Verifying recovery challenge for request: ${requestId}`);

    try {
      const result = await accountRecoveryService.verifyRecoveryChallenge(
        requestId,
        verificationData
      );

      sendOkResponse(res, result.message || 'Verification processed', {
        success: result.success,
        token: result.token,
        expiresAt: result.expiresAt,
      });
    } catch (error: unknown) {
      // Type-safe error handling
      if (error instanceof Error) {
        logger.error(`Error verifying recovery challenge: ${error.message}`, {
          requestId,
          errorDetails: {
            name: error.name,
            message: error.message,
            stack: error.stack,
          },
        });

        // If it's a NotFoundError, we'll pass it through
        if (error instanceof NotFoundError) {
          throw error;
        }
      } else {
        // Handle non-Error objects
        logger.error(`Error verifying recovery challenge: Unknown error type`, {
          requestId,
          errorDetails: String(error),
        });
      }

      // For other errors, rethrow
      throw error;
    }
  });

  /**
   * Complete account recovery process
   * @route POST /recovery/complete
   */
  completeRecovery = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    const { token, newPassword } = req.body;
    const context = {
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    };

    logger.info(`Completing recovery process with token`, {
      context,
      tokenProvided: !!token,
    });

    // Validate required fields
    if (!token) {
      throw new BadRequestError('Recovery token is required', 'TOKEN_REQUIRED');
    }

    if (!newPassword) {
      throw new BadRequestError('New password is required', 'PASSWORD_REQUIRED');
    }

    // Validate password strength
    if (newPassword.length < 8) {
      throw new BadRequestError(
        'Password must be at least 8 characters long',
        'PASSWORD_TOO_SHORT'
      );
    }

    const result = await accountRecoveryService.completeRecovery(token, newPassword, context);

    sendOkResponse(res, result.message, { success: result.success });
  });

  /**
   * Cancel a recovery request
   * @route PUT /recovery/requests/:requestId/cancel
   */
  cancelRecoveryRequest = this.handleAsync(async (req: Request, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    const userId = req.user.id;
    const { requestId } = req.params;

    // Validate request ID
    if (!requestId) {
      throw new BadRequestError('Request ID is required', 'REQUEST_ID_REQUIRED');
    }

    const result = await accountRecoveryService.cancelRecoveryRequest(requestId, userId);

    sendOkResponse(res, result.message, { success: result.success });
  });
  /**
   * Middleware to validate recovery request
   * This demonstrates the use of NextFunction
   */
  validateRecoveryRequest = (req: Request, next: NextFunction): void => {
    const { requestId } = req.params;

    if (!requestId) {
      return next(new BadRequestError('Request ID is required', 'REQUEST_ID_REQUIRED'));
    }

    // If validation passes, proceed to the next middleware/controller
    next();
  };
}

// Create instance
export const recoveryController = new RecoveryController();
