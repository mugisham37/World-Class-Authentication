import { Injectable } from '@tsed/di';
import { logger } from '../../../infrastructure/logging/logger';
import { generateSecureToken } from '../../../infrastructure/security/crypto/encryption';
import { recoveryConfig } from '../../../config/recovery.config';
import { userRepository } from '../../../data/repositories/prisma-user.repository';
import { recoveryMethodRepository } from '../../../data/repositories/recovery-method.repository';
import { recoveryRequestRepository } from '../../../data/repositories/recovery-request.repository';
import { auditLogRepository } from '../../../data/repositories/audit-log.repository';
import {
  BaseRecoveryMethod,
  RecoveryInitiationResult,
  RecoveryVerificationResult,
  RecoveryMethodType,
} from '../recovery-method';
import { RecoveryMethodStatus } from '../../../data/models/recovery-method.model';
import { BadRequestError, NotFoundError } from '../../../utils/error-handling';

/**
 * Email recovery service
 * Implements email-based account recovery
 */
@Injectable()
export class EmailRecoveryService extends BaseRecoveryMethod {
  /**
   * The type of recovery method
   */
  protected readonly type = RecoveryMethodType.EMAIL;

  /**
   * In-memory code storage (replace with Redis in production)
   * Maps requestId to verification data
   */
  private verificationCodes: Map<
    string,
    { code: string; userId: string; email: string; attempts: number; expiresAt: Date }
  > = new Map();

  /**
   * Check if email recovery is available for a user
   * @param userId User ID
   * @returns True if email recovery is available
   */
  async isAvailableForUser(userId: string): Promise<boolean> {
    try {
      // Get user
      const user = await userRepository.findById(userId);
      if (!user) {
        return false;
      }

      // Email recovery is available if the user has a verified email
      return !!user.email && !!user.emailVerified;
    } catch (error) {
      logger.error('Failed to check if email recovery is available', { error, userId });
      return false;
    }
  }

  /**
   * Register email recovery for a user
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
        throw new NotFoundError('User not found');
      }

      // Check if user has a verified email
      if (!user.email || !user.emailVerified) {
        throw new BadRequestError('User must have a verified email to register email recovery');
      }

      // Create recovery method
      const method = await recoveryMethodRepository.create({
        userId,
        type: RecoveryMethodType.EMAIL,
        name: name || 'Email Recovery',
        status: RecoveryMethodStatus.ACTIVE,
        metadata: {
          email: user.email,
          ...data,
        },
      });

      // Log the registration
      await auditLogRepository.create({
        userId,
        action: 'RECOVERY_METHOD_REGISTERED',
        entityType: 'RECOVERY_METHOD',
        entityId: method.id,
        metadata: {
          type: RecoveryMethodType.EMAIL,
          name: method.name,
          email: user.email,
        },
      });

      return method.id;
    } catch (error) {
      logger.error('Failed to register email recovery', { error, userId });
      throw error;
    }
  }

  /**
   * Initiate email recovery
   * @param userId User ID
   * @param requestId Recovery request ID
   * @returns Recovery data
   */
  async initiateRecovery(userId: string, requestId: string): Promise<RecoveryInitiationResult> {
    try {
      // Get user
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Check if user has a verified email
      if (!user.email || !user.emailVerified) {
        throw new BadRequestError('User must have a verified email for email recovery');
      }

      // Get recovery request
      const request = await recoveryRequestRepository.findById(requestId);
      if (!request) {
        throw new NotFoundError('Recovery request not found');
      }

      // Generate a verification code
      const code = this.generateVerificationCode();

      // Store the code with expiration
      const expiresAt = new Date(Date.now() + recoveryConfig.email.codeExpiration * 1000);
      this.verificationCodes.set(requestId, {
        code,
        userId,
        email: user.email,
        attempts: 0,
        expiresAt,
      });

      // In a real implementation, send the code to the user's email
      // For now, we'll just log it
      logger.info('Email recovery code', {
        userId,
        email: user.email,
        code,
        expiresAt,
      });

      // Update request metadata
      await recoveryRequestRepository.update(requestId, {
        metadata: {
          ...request.metadata,
          methodType: RecoveryMethodType.EMAIL,
          email: user.email,
          expiresAt: expiresAt.toISOString(),
        },
      });

      // Log the recovery initiation
      await auditLogRepository.create({
        userId,
        action: 'EMAIL_RECOVERY_INITIATED',
        entityType: 'RECOVERY_REQUEST',
        entityId: requestId,
        metadata: {
          email: user.email,
          expiresAt: expiresAt.toISOString(),
        },
      });

      // Return recovery data
      return {
        metadata: {
          email: user.email,
          expiresAt,
        },
        clientData: {
          email: this.maskEmail(user.email),
          message: 'A recovery code has been sent to your email',
          expiresAt,
          codeLength: code.length,
        },
      };
    } catch (error) {
      logger.error('Failed to initiate email recovery', { error, userId, requestId });
      throw error;
    }
  }

  /**
   * Verify email recovery
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
          message: 'Invalid or expired recovery code',
        };
      }

      // Get the code from verification data
      const { code } = verificationData;
      if (!code) {
        return {
          success: false,
          message: 'Recovery code is required',
        };
      }

      // Check if code is expired
      if (storedData.expiresAt < new Date()) {
        this.verificationCodes.delete(requestId);
        return {
          success: false,
          message: 'Recovery code has expired',
        };
      }

      // Increment attempts
      storedData.attempts += 1;

      // Check if max attempts reached
      if (storedData.attempts > recoveryConfig.email.maxVerificationAttempts) {
        this.verificationCodes.delete(requestId);
        return {
          success: false,
          message: 'Maximum verification attempts reached',
        };
      }

      // Verify the code
      if (storedData.code !== code) {
        return {
          success: false,
          message: `Invalid recovery code. ${recoveryConfig.email.maxVerificationAttempts - storedData.attempts} attempts remaining`,
        };
      }

      // Remove the code
      this.verificationCodes.delete(requestId);

      // Log successful verification
      await auditLogRepository.create({
        userId: storedData.userId,
        action: 'EMAIL_RECOVERY_VERIFIED',
        entityType: 'RECOVERY_REQUEST',
        entityId: requestId,
        metadata: {
          email: storedData.email,
        },
      });

      return {
        success: true,
        message: 'Email verification successful',
      };
    } catch (error) {
      logger.error('Failed to verify email recovery', { error, requestId });
      return {
        success: false,
        message: 'An error occurred during verification',
      };
    }
  }

  /**
   * Generate a random verification code
   * @returns Verification code
   */
  private generateVerificationCode(): string {
    const codeLength = recoveryConfig.email.codeLength || 6;
    const numericOnly = recoveryConfig.email.numericCodesOnly || true;

    // Use secure token if configured
    if (recoveryConfig.email.useSecureToken) {
      return generateSecureToken(codeLength);
    } else if (numericOnly) {
      // Generate numeric code
      const min = Math.pow(10, codeLength - 1);
      const max = Math.pow(10, codeLength) - 1;
      return Math.floor(min + Math.random() * (max - min + 1)).toString();
    } else {
      // Generate alphanumeric code
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Omitting similar-looking characters
      let code = '';
      for (let i = 0; i < codeLength; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      return code;
    }
  }

  /**
   * Mask an email address for privacy
   * @param email Email address
   * @returns Masked email address
   */
  private maskEmail(email: string): string {
    const parts = email.split('@');
    if (parts.length !== 2) {
      return email; // Return original if not a valid email format
    }

    const username = parts[0] || '';
    const domain = parts[1] || '';

    if (!username || !domain) {
      return email; // Return original if username or domain is empty
    }

    const maskedUsername =
      username.length > 2
        ? `${username.substring(0, 2)}${'*'.repeat(username.length - 2)}`
        : username;

    return `${maskedUsername}@${domain}`;
  }
}

// Export a singleton instance
export const emailRecoveryService = new EmailRecoveryService();
