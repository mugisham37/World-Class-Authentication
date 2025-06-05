import { Injectable } from "@tsed/di";
import { logger } from "../../../infrastructure/logging/logger";
import { recoveryConfig } from "../../../config/recovery.config";
import { userRepository } from "../../../data/repositories";
import { RecoveryOptions, AdminRecoveryVerificationData, StoredVerificationData } from "./types";
import { recoveryMethodRepository } from "../../../data/repositories/recovery-method.repository";
import { recoveryRequestRepository } from "../../../data/repositories/recovery-request.repository";
import { auditLogRepository } from "../../../data/repositories/audit-log.repository";
import {
  BaseRecoveryMethod,
  RecoveryInitiationResult,
  RecoveryVerificationResult,
  RecoveryMethodType,
} from "../recovery-method";
import { RecoveryMethodStatus } from "../../../data/models/recovery-method.model";
import { BadRequestError, NotFoundError, UnauthorizedError } from "../../../utils/error-handling";
import { UserRole } from "../../../data/models/user.model";

/**
 * Admin recovery service
 * Implements administrative account recovery
 */
@Injectable()
export class AdminRecoveryService extends BaseRecoveryMethod {
  /**
   * The type of recovery method
   */
  protected readonly type = RecoveryMethodType.ADMIN_RECOVERY;

  /**
   * In-memory verification data storage (replace with Redis in production)
   * Maps requestId to verification data
   */
  private verificationData: Map<string, StoredVerificationData> = new Map();

  /**
   * Check if admin recovery is available for a user
   * @param userId User ID
   * @param options Additional options
   * @returns True if admin recovery is available
   */
  async isAvailableForUser(userId: string, _options: Record<string, any> = {}): Promise<boolean> {
    try {
      // Admin recovery is always available if enabled in config
      return recoveryConfig.admin.enabled;
    } catch (error) {
      logger.error("Failed to check if admin recovery is available", { error, userId });
      return false;
    }
  }

  /**
   * Register admin recovery for a user
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

      // Check if admin recovery is enabled
      if (!recoveryConfig.admin.enabled) {
        throw new BadRequestError("Admin recovery is not enabled");
      }

      // Create recovery method
      const method = await recoveryMethodRepository.create({
        userId,
        type: RecoveryMethodType.ADMIN_RECOVERY,
        name: name || "Admin Recovery",
        status: RecoveryMethodStatus.ACTIVE,
        metadata: {
          ...data,
        },
      });

      // Log the registration
      await auditLogRepository.create({
        userId,
        action: "RECOVERY_METHOD_REGISTERED",
        entityType: "RECOVERY_METHOD",
        entityId: method.id,
        metadata: {
          type: RecoveryMethodType.ADMIN_RECOVERY,
          name: method.name,
        },
      });

      return method.id;
    } catch (error) {
      logger.error("Failed to register admin recovery", { error, userId });
      throw error;
    }
  }

  /**
   * Initiate admin recovery
   * @param userId User ID
   * @param requestId Recovery request ID
   * @param options Additional options
   * @returns Recovery data
   */
  async initiateRecovery(
    userId: string,
    requestId: string,
    options: RecoveryOptions = {}
  ): Promise<RecoveryInitiationResult> {
    try {
      // Check if admin recovery is enabled
      if (!recoveryConfig.admin.enabled) {
        throw new BadRequestError("Admin recovery is not enabled");
      }

      // Get user
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError("User not found");
      }

      // Get recovery request
      const request = await recoveryRequestRepository.findById(requestId);
      if (!request) {
        throw new NotFoundError("Recovery request not found");
      }

      // Verify admin privileges
      const adminId = options['adminId'];
      if (!adminId) {
        throw new BadRequestError("Admin ID is required");
      }

      const admin = await userRepository.findById(adminId);
      if (!admin) {
        throw new NotFoundError("Admin user not found");
      }

      if (admin.role !== UserRole.ADMIN && admin.role !== UserRole.SUPER_ADMIN) {
        throw new UnauthorizedError("Administrative privileges required");
      }

      // Check if minimum admin role is met
      if (
        recoveryConfig.admin.minApproverRole === "SUPER_ADMIN" &&
        admin.role !== UserRole.SUPER_ADMIN
      ) {
        throw new UnauthorizedError("Super admin privileges required for recovery approval");
      }

      // Check if reason is provided when required
      const reason = options['reason'];
      if (recoveryConfig.admin.requireReason && (!reason || reason.trim().length === 0)) {
        throw new BadRequestError("Recovery reason is required");
      }

      // Store verification data
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
      this.verificationData.set(requestId, {
        userId,
        adminId,
        reason: reason || "Administrative recovery",
        expiresAt,
      });

      // Update request metadata
      await recoveryRequestRepository.update(requestId, {
        metadata: {
          ...request.metadata,
          methodType: RecoveryMethodType.ADMIN_RECOVERY,
          adminId,
          reason,
          expiresAt: expiresAt.toISOString(),
        },
      });

      // Log the recovery initiation
      await auditLogRepository.create({
        userId: adminId,
        action: "ADMIN_RECOVERY_INITIATED",
        entityType: "RECOVERY_REQUEST",
        entityId: requestId,
        metadata: {
          targetUserId: userId,
          targetUserEmail: user.email,
          reason: reason || "Administrative recovery",
        },
      });

      // Return recovery data
      return {
        metadata: {
          adminId,
          reason,
          expiresAt,
        },
        clientData: {
          message: "Administrative recovery initiated",
          targetUser: user.email,
          requiresApproval: recoveryConfig.admin.requireMultipleApprovals,
          requiredApprovals: recoveryConfig.admin.requiredApprovals,
          expiresAt,
        },
      };
    } catch (error) {
      logger.error("Failed to initiate admin recovery", { error, userId, requestId });
      throw error;
    }
  }

  /**
   * Verify admin recovery
   * @param requestId Recovery request ID
   * @param verificationData Verification data
   * @returns Verification result
   */
  async verifyRecovery(
    requestId: string,
    verificationData: AdminRecoveryVerificationData
  ): Promise<RecoveryVerificationResult> {
    try {
      // Get stored verification data
      const storedData = this.verificationData.get(requestId);
      if (!storedData) {
        return {
          success: false,
          message: "Invalid or expired recovery session",
        };
      }

      // Check if expired
      if (storedData.expiresAt < new Date()) {
        this.verificationData.delete(requestId);
        return {
          success: false,
          message: "Recovery session has expired",
        };
      }

      // Get verification data
      const { adminId, adminCode, confirmationCode } = verificationData;

      // Verify admin ID
      if (!adminId) {
        return {
          success: false,
          message: "Admin ID is required",
        };
      }

      if (adminId !== storedData.adminId) {
        return {
          success: false,
          message: "Admin ID does not match the initiating admin",
        };
      }

      // In a real implementation, verify the admin code against a secure system
      // For now, we'll use a simple check
      if (recoveryConfig.admin.requireMultipleApprovals) {
        // Check if confirmation code is provided
        if (!confirmationCode) {
          return {
            success: false,
            message: "Confirmation code is required",
          };
        }

        // In a real implementation, verify the confirmation code
        // For now, we'll use a simple check
        if (confirmationCode !== "ADMIN_CONFIRMATION_CODE") {
          return {
            success: false,
            message: "Invalid confirmation code",
          };
        }
      } else {
        // Check if admin code is provided
        if (!adminCode) {
          return {
            success: false,
            message: "Admin verification code is required",
          };
        }

        // In a real implementation, verify the admin code
        // For now, we'll use a simple check
        if (adminCode !== "ADMIN_RECOVERY_CODE") {
          return {
            success: false,
            message: "Invalid admin verification code",
          };
        }
      }

      // Remove verification data
      this.verificationData.delete(requestId);

      // Log the successful verification
      await auditLogRepository.create({
        userId: adminId,
        action: "ADMIN_RECOVERY_VERIFIED",
        entityType: "RECOVERY_REQUEST",
        entityId: requestId,
        metadata: {
          targetUserId: storedData.userId,
          reason: storedData.reason,
        },
      });

      return {
        success: true,
        message: "Admin recovery verification successful",
      };
    } catch (error) {
      logger.error("Failed to verify admin recovery", { error, requestId });
      return {
        success: false,
        message: "An error occurred during verification",
      };
    }
  }

  /**
   * Approve a recovery request as an admin
   * @param requestId Recovery request ID
   * @param adminId Admin user ID
   * @param notes Approval notes
   * @returns Approval result
   */
  async approveRecoveryRequest(
    requestId: string,
    adminId: string,
    notes?: string
  ): Promise<{ success: boolean; message: string }> {
    try {
      // Get recovery request
      const request = await recoveryRequestRepository.findById(requestId);
      if (!request) {
        throw new NotFoundError("Recovery request not found");
      }

      // Verify admin privileges
      const admin = await userRepository.findById(adminId);
      if (!admin) {
        throw new NotFoundError("Admin user not found");
      }

      if (admin.role !== UserRole.ADMIN && admin.role !== UserRole.SUPER_ADMIN) {
        throw new UnauthorizedError("Administrative privileges required");
      }

      // Check if minimum admin role is met
      if (
        recoveryConfig.admin.minApproverRole === "SUPER_ADMIN" &&
        admin.role !== UserRole.SUPER_ADMIN
      ) {
        throw new UnauthorizedError("Super admin privileges required for recovery approval");
      }

      // In a real implementation, create an admin approval record
      // For now, we'll just log it
      logger.info("Admin approval for recovery request", {
        requestId,
        adminId,
        notes,
      });

      // Log the approval
      await auditLogRepository.create({
        userId: adminId,
        action: "ADMIN_RECOVERY_APPROVED",
        entityType: "RECOVERY_REQUEST",
        entityId: requestId,
        metadata: {
          targetUserId: request.userId,
          notes,
        },
      });

      return {
        success: true,
        message: "Recovery request approved successfully",
      };
    } catch (error) {
      logger.error("Failed to approve recovery request", { error, requestId, adminId });
      throw error;
    }
  }

  /**
   * Deny a recovery request as an admin
   * @param requestId Recovery request ID
   * @param adminId Admin user ID
   * @param reason Denial reason
   * @returns Denial result
   */
  async denyRecoveryRequest(
    requestId: string,
    adminId: string,
    reason: string
  ): Promise<{ success: boolean; message: string }> {
    try {
      // Get recovery request
      const request = await recoveryRequestRepository.findById(requestId);
      if (!request) {
        throw new NotFoundError("Recovery request not found");
      }

      // Verify admin privileges
      const admin = await userRepository.findById(adminId);
      if (!admin) {
        throw new NotFoundError("Admin user not found");
      }

      if (admin.role !== UserRole.ADMIN && admin.role !== UserRole.SUPER_ADMIN) {
        throw new UnauthorizedError("Administrative privileges required");
      }

      // In a real implementation, create an admin denial record
      // For now, we'll just log it
      logger.info("Admin denial for recovery request", {
        requestId,
        adminId,
        reason,
      });

      // Log the denial
      await auditLogRepository.create({
        userId: adminId,
        action: "ADMIN_RECOVERY_DENIED",
        entityType: "RECOVERY_REQUEST",
        entityId: requestId,
        metadata: {
          targetUserId: request.userId,
          reason,
        },
      });

      return {
        success: true,
        message: "Recovery request denied successfully",
      };
    } catch (error) {
      logger.error("Failed to deny recovery request", { error, requestId, adminId });
      throw error;
    }
  }
}

// Export a singleton instance
export const adminRecoveryService = new AdminRecoveryService();
