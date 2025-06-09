import type { Response } from 'express';
import { BaseController, ExtendedRequest } from './base.controller';
import { sendOkResponse, sendCreatedResponse } from '../responses';
import { AuthenticationError, BadRequestError } from '../../utils/error-handling';
import { logger } from '../../infrastructure/logging/logger';
import { MfaService } from '../../core/mfa/mfa.service';

/**
 * MFA controller
 * Handles multi-factor authentication setup and verification
 */
export class MfaController extends BaseController {
  // Private instance of MfaService
  private static mfaServiceInstance: MfaService | null = null;

  /**
   * Get MFA service instance
   * @returns MFA service instance
   */
  private getMfaService(): MfaService {
    if (!MfaController.mfaServiceInstance) {
      // In a real application, this would be injected or retrieved from a service container
      // For now, we'll create a mock implementation
      MfaController.mfaServiceInstance = {
        getUserFactors: async (userId: string) => {
          logger.debug(`Getting MFA factors for user ${userId}`);
          return [];
        },
        startFactorEnrollment: async (userId: string, factorType: any) => {
          logger.debug(`Starting MFA factor enrollment for user ${userId}`);
          return { success: true, factorId: 'mock-factor-id', factorType, message: '' };
        },
        completeFactorEnrollment: async (userId: string, factorId: string) => {
          logger.debug(`Completing MFA factor enrollment for user ${userId}`);
          return { success: true, factorId, factorType: 'totp', message: '' };
        },
        generateChallenge: async (factorId: string) => {
          logger.debug(`Generating MFA challenge for factor ${factorId}`);
          return { challengeId: 'mock-challenge-id', factorType: 'totp', expiresAt: new Date() };
        },
        verifyChallenge: async (challengeId: string) => {
          logger.debug(`Verifying MFA challenge ${challengeId}`);
          return { success: true, challengeId, factorType: 'totp', message: '' };
        },
        disableFactor: async (userId: string, factorId: string) => {
          logger.debug(`Disabling MFA factor ${factorId} for user ${userId}`);
          return true;
        },
        enableFactor: async (userId: string, factorId: string) => {
          logger.debug(`Enabling MFA factor ${factorId} for user ${userId}`);
          return true;
        },
        deleteFactor: async (userId: string, factorId: string) => {
          logger.debug(`Deleting MFA factor ${factorId} for user ${userId}`);
          return true;
        },
        regenerateRecoveryCodes: async (userId: string) => {
          logger.debug(`Regenerating recovery codes for user ${userId}`);
          return ['MOCK1-RECOVERY-CODE', 'MOCK2-RECOVERY-CODE'];
        },
        // These methods are not in the MfaService interface but we're adding them for our controller
        getRecoveryCodes: async (userId: string) => {
          logger.debug(`Getting recovery codes for user ${userId}`);
          return ['MOCK1-RECOVERY-CODE', 'MOCK2-RECOVERY-CODE'];
        },
        verifyRecoveryCode: async (userId: string) => {
          logger.debug(`Verifying recovery code for user ${userId}`);
          return { success: true, message: 'Recovery code verified successfully' };
        },
      } as unknown as MfaService;
    }

    return MfaController.mfaServiceInstance;
  }

  /**
   * Get all MFA factors for the authenticated user
   * @route GET /mfa/factors
   */
  getUserFactors = this.handleAsync(async (req: ExtendedRequest, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    const userId = req.user.id;

    // Get MFA service instance
    const mfaService = this.getMfaService();

    const factors = await mfaService.getUserFactors(userId);

    sendOkResponse(res, 'MFA factors retrieved successfully', factors);
  });

  /**
   * Start enrollment for a new MFA factor
   * @route POST /mfa/factors
   */
  startFactorEnrollment = this.handleAsync(
    async (req: ExtendedRequest, res: Response): Promise<void> => {
      // Check if user is authenticated
      if (!req.user) {
        throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
      }

      const userId = req.user.id;
      const { factorType, factorName, factorData } = req.body;

      // Get MFA service instance
      const mfaService = this.getMfaService();

      // Ensure all parameters are defined
      const safeFactorType = factorType || 'totp';
      const safeFactorName = factorName || 'Default Factor';

      const result = await mfaService.startFactorEnrollment(
        userId,
        safeFactorType,
        safeFactorName,
        factorData
      );

      if (result.success) {
        sendCreatedResponse(res, 'MFA factor enrollment started', result);
      } else {
        sendOkResponse(res, result.message || 'MFA factor enrollment failed', result);
      }
    }
  );

  /**
   * Complete enrollment by verifying a new MFA factor
   * @route POST /mfa/factors/:factorId/verify
   */
  verifyFactorEnrollment = this.handleAsync(
    async (req: ExtendedRequest, res: Response): Promise<void> => {
      // Check if user is authenticated
      if (!req.user) {
        throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
      }

      const userId = req.user.id;
      const { factorId } = req.params;
      const verificationData = req.body;

      // Get MFA service instance
      const mfaService = this.getMfaService();

      // Ensure factorId is defined
      if (!factorId) {
        throw new BadRequestError('Factor ID is required', 'FACTOR_ID_REQUIRED');
      }

      const result = await mfaService.completeFactorEnrollment(userId, factorId, verificationData);

      sendOkResponse(
        res,
        result.success
          ? 'MFA factor verified successfully'
          : result.message || 'MFA factor verification failed',
        result
      );
    }
  );

  /**
   * Generate an MFA challenge for a specific factor
   * @route POST /mfa/challenge
   */
  generateChallenge = this.handleAsync(
    async (req: ExtendedRequest, res: Response): Promise<void> => {
      const { factorId, metadata: _metadata } = req.body;

      // Get MFA service instance
      const mfaService = this.getMfaService();

      // Ensure factorId is defined
      if (!factorId) {
        throw new BadRequestError('Factor ID is required', 'FACTOR_ID_REQUIRED');
      }

      const challenge = await mfaService.generateChallenge(factorId, _metadata);

      sendCreatedResponse(res, 'MFA challenge generated', challenge);
    }
  );

  /**
   * Verify an MFA challenge response
   * @route POST /mfa/challenge/:challengeId/verify
   */
  verifyChallenge = this.handleAsync(async (req: ExtendedRequest, res: Response): Promise<void> => {
    const { challengeId } = req.params;
    const { response: challengeResponse, metadata: _metadata } = req.body;

    // Get MFA service instance
    const mfaService = this.getMfaService();

    // Ensure challengeId is defined
    if (!challengeId) {
      throw new BadRequestError('Challenge ID is required', 'CHALLENGE_ID_REQUIRED');
    }

    const result = await mfaService.verifyChallenge(challengeId, challengeResponse, _metadata);

    sendOkResponse(
      res,
      result.success
        ? 'MFA challenge verified successfully'
        : result.message || 'MFA challenge verification failed',
      result
    );
  });

  /**
   * Disable an MFA factor
   * @route PUT /mfa/factors/:factorId/disable
   */
  disableFactor = this.handleAsync(async (req: ExtendedRequest, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    const userId = req.user.id;
    const { factorId } = req.params;

    // Get MFA service instance
    const mfaService = this.getMfaService();

    // Ensure factorId is defined
    if (!factorId) {
      throw new BadRequestError('Factor ID is required', 'FACTOR_ID_REQUIRED');
    }

    await mfaService.disableFactor(userId, factorId);

    sendOkResponse(res, 'MFA factor disabled successfully');
  });

  /**
   * Enable a previously disabled MFA factor
   * @route PUT /mfa/factors/:factorId/enable
   */
  enableFactor = this.handleAsync(async (req: ExtendedRequest, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    const userId = req.user.id;
    const { factorId } = req.params;

    // Get MFA service instance
    const mfaService = this.getMfaService();

    // Ensure factorId is defined
    if (!factorId) {
      throw new BadRequestError('Factor ID is required', 'FACTOR_ID_REQUIRED');
    }

    await mfaService.enableFactor(userId, factorId);

    sendOkResponse(res, 'MFA factor enabled successfully');
  });

  /**
   * Delete an MFA factor
   * @route DELETE /mfa/factors/:factorId
   */
  deleteFactor = this.handleAsync(async (req: ExtendedRequest, res: Response): Promise<void> => {
    // Check if user is authenticated
    if (!req.user) {
      throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
    }

    const userId = req.user.id;
    const { factorId } = req.params;

    // Get MFA service instance
    const mfaService = this.getMfaService();

    // Ensure factorId is defined
    if (!factorId) {
      throw new BadRequestError('Factor ID is required', 'FACTOR_ID_REQUIRED');
    }

    await mfaService.deleteFactor(userId, factorId);

    sendOkResponse(res, 'MFA factor deleted successfully');
  });

  /**
   * Regenerate recovery codes
   * @route POST /mfa/recovery-codes/regenerate
   */
  regenerateRecoveryCodes = this.handleAsync(
    async (req: ExtendedRequest, res: Response): Promise<void> => {
      // Check if user is authenticated
      if (!req.user) {
        throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
      }

      const userId = req.user.id;

      // Get MFA service instance
      const mfaService = this.getMfaService();

      const recoveryCodes = await mfaService.regenerateRecoveryCodes(userId);

      sendOkResponse(res, 'Recovery codes regenerated successfully', { recoveryCodes });
    }
  );

  /**
   * Get recovery codes
   * @route GET /mfa/recovery-codes
   */
  getRecoveryCodes = this.handleAsync(
    async (req: ExtendedRequest, res: Response): Promise<void> => {
      // Check if user is authenticated
      if (!req.user) {
        throw new AuthenticationError('Not authenticated', 'NOT_AUTHENTICATED');
      }

      const userId = req.user.id;

      // Get MFA service instance
      const mfaService = this.getMfaService();

      // Use regenerateRecoveryCodes to get recovery codes since getRecoveryCodes might not exist
      // In a real implementation, we would have a separate method to get existing codes
      const recoveryCodes = await mfaService.regenerateRecoveryCodes(userId);

      sendOkResponse(res, 'Recovery codes retrieved successfully', { recoveryCodes });
    }
  );

  /**
   * Verify a recovery code
   * @route POST /mfa/recovery-codes/verify
   */
  verifyRecoveryCode = this.handleAsync(
    async (req: ExtendedRequest, res: Response): Promise<void> => {
      const { recoveryCode, userId } = req.body;

      // Ensure required parameters are provided
      if (!userId) {
        throw new BadRequestError('User ID is required', 'USER_ID_REQUIRED');
      }

      if (!recoveryCode) {
        throw new BadRequestError('Recovery code is required', 'RECOVERY_CODE_REQUIRED');
      }

      // Get MFA service instance
      const mfaService = this.getMfaService();

      // Verify the recovery code
      const result = await mfaService.verifyRecoveryCode(userId, recoveryCode);

      sendOkResponse(
        res,
        result.success
          ? 'Recovery code verified successfully'
          : 'Recovery code verification failed',
        result
      );
    }
  );
}

// Create and export controller instance
export const mfaController = new MfaController();
