import { Injectable } from "@tsed/di";
import { logger } from "../../infrastructure/logging/logger";
import { recoveryConfig } from "../../config/recovery.config";
import { userRepository } from "../../data/repositories/user.repository";
import { recoveryMethodRepository } from "../../data/repositories/recovery-method.repository";
import { recoveryRequestRepository } from "../../data/repositories/recovery-request.repository";
import { recoveryTokenRepository } from "../../data/repositories/recovery-token.repository";
import { auditLogRepository } from "../../data/repositories/audit-log.repository";
import { emailRecoveryService } from "./methods/email-recovery.service";
import { securityQuestionsService } from "./methods/security-questions.service";
import { trustedContactService } from "./methods/trusted-contact.service";
import { adminRecoveryService } from "./methods/admin-recovery.service";
import { RecoveryMethodType } from "./recovery-method";
import { RecoveryContext } from "./types";
import { RecoveryMethodStatus } from "../../data/models/recovery-method.model";
import { RecoveryRequestStatus, RecoveryRequestType } from "../../data/models/recovery-request.model";
import { RecoveryTokenType } from "../../data/models/recovery-token.model";
import { BadRequestError, NotFoundError, UnauthorizedError } from "../../utils/error-handling";
import { generateSecureToken } from "../../infrastructure/security/crypto/encryption";

/**
 * Account recovery service
 * Orchestrates the account recovery process using various recovery methods
 */
@Injectable()
export class AccountRecoveryService {
  /**
   * Map of recovery method types to their service implementations
   */
  private recoveryMethodServices = new Map();

  constructor() {
    // Register recovery method services
    this.recoveryMethodServices.set(RecoveryMethodType.EMAIL, emailRecoveryService);
    this.recoveryMethodServices.set(RecoveryMethodType.SECURITY_QUESTIONS, securityQuestionsService);
    this.recoveryMethodServices.set(RecoveryMethodType.TRUSTED_CONTACTS, trustedContactService);
    this.recoveryMethodServices.set(RecoveryMethodType.ADMIN_RECOVERY, adminRecoveryService);
  }

  /**
   * Get all recovery methods for a user
   * @param userId User ID
   * @returns Array of recovery methods
   */
  async getUserRecoveryMethods(userId: string) {
    try {
      return await recoveryMethodRepository.findByUserId(userId);
    } catch (error) {
      logger.error("Failed to get user recovery methods", { error, userId });
      throw error;
    }
  }

  /**
   * Get active recovery methods for a user
   * @param userId User ID
   * @returns Array of active recovery methods
   */
  async getActiveRecoveryMethods(userId: string) {
    try {
      return await recoveryMethodRepository.findActiveByUserId(userId);
    } catch (error) {
      logger.error("Failed to get active recovery methods", { error, userId });
      throw error;
    }
  }

  /**
   * Get available recovery methods for a user
   * @param userId User ID
   * @returns Array of available recovery method types
   */
  async getAvailableRecoveryMethods(userId: string): Promise<RecoveryMethodType[]> {
    try {
      const availableMethods: RecoveryMethodType[] = [];

      // Check each recovery method type
      for (const [type, service] of this.recoveryMethodServices.entries()) {
        if (await service.isAvailableForUser(userId)) {
          availableMethods.push(type);
        }
      }

      return availableMethods;
    } catch (error) {
      logger.error("Failed to get available recovery methods", { error, userId });
      throw error;
    }
  }

  /**
   * Register a new recovery method for a user
   * @param userId User ID
   * @param type Recovery method type
   * @param name Name for the recovery method
   * @param data Additional method-specific data
   * @returns Created recovery method
   */
  async registerRecoveryMethod(
    userId: string,
    type: RecoveryMethodType,
    name: string,
    data?: Record<string, any>
  ) {
    try {
      // Check if user exists
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError("User not found");
      }

      // Get the recovery method service
      const service = this.recoveryMethodServices.get(type);
      if (!service) {
        throw new BadRequestError(`Unsupported recovery method type: ${type}`);
      }

      // Register the recovery method
      const methodId = await service.register(userId, name, data);

      // Log the registration
      await auditLogRepository.create({
        userId,
        action: "RECOVERY_METHOD_REGISTERED",
        entityType: "RECOVERY_METHOD",
        entityId: methodId,
        metadata: {
          type,
          name,
        },
      });

      return await recoveryMethodRepository.findById(methodId);
    } catch (error) {
      logger.error("Failed to register recovery method", { error, userId, type });
      throw error;
    }
  }

  /**
   * Initiate account recovery process
   * @param email User email
   * @param methodType Recovery method type to use
   * @param context Additional context (IP, user agent, etc.)
   * @returns Recovery request data
   */
  async initiateRecovery(
    email: string,
    methodType: RecoveryMethodType,
    context: RecoveryContext = {}
  ) {
    try {
      // Find user by email
      const user = await userRepository.findByEmail(email);
      if (!user) {
        // For security reasons, don't reveal that the email doesn't exist
        // Instead, pretend the recovery was initiated
        logger.info(`Recovery attempt for non-existent email: ${email}`);
        return {
          success: true,
          message: "If an account with this email exists, recovery instructions have been sent.",
        };
      }

      // Check for existing active recovery requests
      const activeRequests = await recoveryRequestRepository.findActiveByUserId(user.id);
      if (activeRequests.length >= recoveryConfig.general.maxConcurrentRecoveries) {
        throw new BadRequestError(
          `Maximum number of concurrent recovery requests (${recoveryConfig.general.maxConcurrentRecoveries}) reached`
        );
      }

      // Check cooldown period between recoveries
      const recentRequests = await recoveryRequestRepository.findRecentByUserId(
        user.id,
        recoveryConfig.general.cooldownBetweenRecoveries
      );
      if (recentRequests.length > 0) {
        throw new BadRequestError("Account recovery was recently initiated. Please wait before trying again.");
      }

      // Get the recovery method service
      const service = this.recoveryMethodServices.get(methodType);
      if (!service) {
        throw new BadRequestError(`Unsupported recovery method type: ${methodType}`);
      }

      // Check if the recovery method is available for the user
      const isAvailable = await service.isAvailableForUser(user.id);
      if (!isAvailable) {
        throw new BadRequestError(`Recovery method ${methodType} is not available for this user`);
      }

      // Create recovery request
      const recoveryRequest = await recoveryRequestRepository.create({
        userId: user.id,
        type: RecoveryRequestType.ACCOUNT_RECOVERY,
        status: RecoveryRequestStatus.PENDING,
        ipAddress: context['ipAddress'],
        userAgent: context['userAgent'],
        metadata: {
          methodType,
          email,
        },
      });

      // Log the recovery initiation
      await auditLogRepository.create({
        userId: user.id,
        action: "ACCOUNT_RECOVERY_INITIATED",
        entityType: "RECOVERY_REQUEST",
        entityId: recoveryRequest.id,
        ipAddress: context['ipAddress'],
        userAgent: context['userAgent'],
        metadata: {
          methodType,
        },
      });

      // Initiate recovery with the selected method
      const recoveryData = await service.initiateRecovery(user.id, recoveryRequest.id, context);

      // Return client data
      return {
        success: true,
        requestId: recoveryRequest.id,
        ...recoveryData.clientData,
      };
    } catch (error) {
      logger.error("Failed to initiate account recovery", { error, email, methodType });
      throw error;
    }
  }

  /**
   * Verify recovery challenge
   * @param requestId Recovery request ID
   * @param verificationData Verification data (e.g., security answers, verification code)
   * @returns Verification result with recovery token
   */
  async verifyRecoveryChallenge(requestId: string, verificationData: Record<string, any>) {
    try {
      // Find recovery request
      const request = await recoveryRequestRepository.findById(requestId);
      if (!request) {
        throw new NotFoundError("Recovery request not found");
      }

      // Check if request is still pending
      if (request.status !== RecoveryRequestStatus.PENDING) {
        throw new BadRequestError(`Recovery request is already ${request.status.toLowerCase()}`);
      }

      // Get method type from request metadata
      const methodType = request.metadata?.['methodType'] as RecoveryMethodType;
      if (!methodType) {
        throw new BadRequestError("Invalid recovery request: missing method type");
      }

      // Get the recovery method service
      const service = this.recoveryMethodServices.get(methodType);
      if (!service) {
        throw new BadRequestError(`Unsupported recovery method type: ${methodType}`);
      }

      // Verify with the selected method
      const verificationResult = await service.verifyRecovery(requestId, verificationData);

      if (verificationResult.success) {
        // Generate recovery token
        const token = generateSecureToken(recoveryConfig.general.recoveryTokenLength);
        const expiresAt = new Date(Date.now() + recoveryConfig.general.recoveryTokenExpiration * 1000);

        // Store recovery token
        const recoveryToken = await recoveryTokenRepository.create({
          token,
          type: RecoveryTokenType.ACCOUNT_RECOVERY,
          userId: request.userId,
          expiresAt,
          metadata: {
            requestId,
            methodType,
          },
        });

        // Update recovery request status
        await recoveryRequestRepository.update(requestId, {
          status: RecoveryRequestStatus.APPROVED,
        });

        // Log successful verification
        await auditLogRepository.create({
          userId: request.userId,
          action: "ACCOUNT_RECOVERY_VERIFIED",
          entityType: "RECOVERY_REQUEST",
          entityId: requestId,
          metadata: {
            methodType,
            tokenId: recoveryToken.id,
          },
        });

        return {
          success: true,
          token,
          expiresAt,
          message: "Recovery verification successful. Use the token to reset your account.",
        };
      } else {
        // Log failed verification
        await auditLogRepository.create({
          userId: request.userId,
          action: "ACCOUNT_RECOVERY_VERIFICATION_FAILED",
          entityType: "RECOVERY_REQUEST",
          entityId: requestId,
          metadata: {
            methodType,
            error: verificationResult.message,
          },
        });

        return verificationResult;
      }
    } catch (error) {
      logger.error("Failed to verify recovery challenge", { error, requestId });
      throw error;
    }
  }

  /**
   * Complete account recovery process
   * @param token Recovery token
   * @param newPassword New password for the account
   * @param context Additional context (IP, user agent, etc.)
   * @returns Success status
   */
  async completeRecovery(token: string, newPassword: string, context: RecoveryContext = {}) {
    try {
      // Find recovery token
      const recoveryToken = await recoveryTokenRepository.findByToken(token);
      if (!recoveryToken) {
        throw new NotFoundError("Recovery token not found");
      }

      // Check if token has expired
      if (recoveryToken.expiresAt < new Date()) {
        throw new BadRequestError("Recovery token has expired");
      }

      // Check if token has already been used
      if (recoveryToken.usedAt) {
        throw new BadRequestError("Recovery token has already been used");
      }

      // Get user ID from token
      const userId = recoveryToken.userId;
      if (!userId) {
        throw new BadRequestError("Invalid recovery token: missing user ID");
      }

      // Find user
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError("User not found");
      }

      // Reset user password
      await userRepository.resetPassword(userId, newPassword);

      // Mark token as used
      await recoveryTokenRepository.markAsUsed(token);

      // Update recovery request status if request ID is in metadata
      const requestId = recoveryToken.metadata?.['requestId'];
      if (requestId) {
        await recoveryRequestRepository.update(requestId, {
          status: RecoveryRequestStatus.COMPLETED,
          completedAt: new Date(),
        });
      }

      // Log successful recovery
      await auditLogRepository.create({
        userId,
        action: "ACCOUNT_RECOVERY_COMPLETED",
        ipAddress: context['ipAddress'],
        userAgent: context['userAgent'],
        metadata: {
          tokenId: recoveryToken.id,
          requestId,
        },
      });

      return {
        success: true,
        message: "Account recovery completed successfully. You can now log in with your new password.",
      };
    } catch (error) {
      logger.error("Failed to complete account recovery", { error, token });
      throw error;
    }
  }

  /**
   * Cancel a recovery request
   * @param requestId Recovery request ID
   * @param userId User ID (for authorization)
   * @returns Success status
   */
  async cancelRecoveryRequest(requestId: string, userId: string) {
    try {
      // Find recovery request
      const request = await recoveryRequestRepository.findById(requestId);
      if (!request) {
        throw new NotFoundError("Recovery request not found");
      }

      // Check if user is authorized to cancel this request
      if (request.userId !== userId) {
        throw new UnauthorizedError("Unauthorized to cancel this recovery request");
      }

      // Check if request can be cancelled
      if (request.status !== RecoveryRequestStatus.PENDING) {
        throw new BadRequestError(`Cannot cancel recovery request with status: ${request.status}`);
      }

      // Update request status
      await recoveryRequestRepository.update(requestId, {
        status: RecoveryRequestStatus.CANCELLED,
      });

      // Log cancellation
      await auditLogRepository.create({
        userId,
        action: "RECOVERY_REQUEST_CANCELLED",
        entityType: "RECOVERY_REQUEST",
        entityId: requestId,
      });

      return {
        success: true,
        message: "Recovery request cancelled successfully",
      };
    } catch (error) {
      logger.error("Failed to cancel recovery request", { error, requestId, userId });
      throw error;
    }
  }

  /**
   * Disable a recovery method
   * @param userId User ID
   * @param methodId Recovery method ID
   * @returns Success status
   */
  async disableRecoveryMethod(userId: string, methodId: string) {
    try {
      // Find recovery method
      const method = await recoveryMethodRepository.findById(methodId);
      if (!method) {
        throw new NotFoundError("Recovery method not found");
      }

      // Check if user is authorized
      if (method.userId !== userId) {
        throw new UnauthorizedError("Unauthorized to modify this recovery method");
      }

      // Update method status
      await recoveryMethodRepository.update(methodId, {
        status: RecoveryMethodStatus.DISABLED,
      });

      // Log disabling
      await auditLogRepository.create({
        userId,
        action: "RECOVERY_METHOD_DISABLED",
        entityType: "RECOVERY_METHOD",
        entityId: methodId,
        metadata: {
          type: method.type,
          name: method.name,
        },
      });

      return {
        success: true,
        message: "Recovery method disabled successfully",
      };
    } catch (error) {
      logger.error("Failed to disable recovery method", { error, userId, methodId });
      throw error;
    }
  }

  /**
   * Enable a previously disabled recovery method
   * @param userId User ID
   * @param methodId Recovery method ID
   * @returns Success status
   */
  async enableRecoveryMethod(userId: string, methodId: string) {
    try {
      // Find recovery method
      const method = await recoveryMethodRepository.findById(methodId);
      if (!method) {
        throw new NotFoundError("Recovery method not found");
      }

      // Check if user is authorized
      if (method.userId !== userId) {
        throw new UnauthorizedError("Unauthorized to modify this recovery method");
      }

      // Check if method is disabled
      if (method.status !== RecoveryMethodStatus.DISABLED) {
        throw new BadRequestError("Recovery method is not disabled");
      }

      // Update method status
      await recoveryMethodRepository.update(methodId, {
        status: RecoveryMethodStatus.ACTIVE,
      });

      // Log enabling
      await auditLogRepository.create({
        userId,
        action: "RECOVERY_METHOD_ENABLED",
        entityType: "RECOVERY_METHOD",
        entityId: methodId,
        metadata: {
          type: method.type,
          name: method.name,
        },
      });

      return {
        success: true,
        message: "Recovery method enabled successfully",
      };
    } catch (error) {
      logger.error("Failed to enable recovery method", { error, userId, methodId });
      throw error;
    }
  }
}

// Export a singleton instance
export const accountRecoveryService = new AccountRecoveryService();
