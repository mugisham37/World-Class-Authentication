import { Injectable } from '@tsed/di';
import { v4 as uuidv4 } from 'uuid';
import type { MfaFactorRepository } from '../../../data/repositories/mfa-factor.repository';
import type { MfaChallengeRepository } from '../../../data/repositories/mfa-challenge.repository';
import {
  MfaFactorType,
  MfaFactorStatus,
  type MfaEnrollmentResult,
  type MfaVerificationResult,
} from '../mfa-factor-types';
import { mfaConfig } from '../../../config/mfa-config';
import { logger } from '../../../infrastructure/logging/logger';
import { BadRequestError, NotFoundError } from '../../../utils/error-handling';

@Injectable()
export class PushNotificationService {
  constructor(
    private mfaFactorRepository: MfaFactorRepository,
    private mfaChallengeRepository: MfaChallengeRepository
  ) {}

  /**
   * Start push notification MFA enrollment process
   * @param userId User ID
   * @param factorName Name for the factor
   * @param deviceToken Device token for push notifications
   * @returns Enrollment result
   */
  async startEnrollment(
    userId: string,
    factorName: string,
    deviceToken: string
  ): Promise<MfaEnrollmentResult> {
    try {
      // Create factor record
      const factor = await this.mfaFactorRepository.create({
        userId,
        type: MfaFactorType.PUSH_NOTIFICATION,
        name: factorName,
        deviceToken,
        status: MfaFactorStatus.PENDING,
        metadata: {
          provider: mfaConfig.pushNotification.provider,
          enrolledAt: new Date().toISOString(),
        },
      });

      // Send test notification to verify device token
      const verificationCode = this.generateVerificationCode();
      await this.sendPushNotification(deviceToken, {
        title: 'Verification Required',
        body: 'Enter this code to verify your device: ' + verificationCode,
        data: {
          type: 'verification',
          code: verificationCode,
          factorId: factor.id,
        },
      });

      return {
        success: true,
        factorId: factor.id,
        factorType: MfaFactorType.PUSH_NOTIFICATION,
        message: 'Push notification verification sent to your device',
      };
    } catch (error: any) {
      logger.error('Failed to start push notification MFA enrollment', { error, userId });
      return {
        success: false,
        message: 'Failed to start push notification MFA enrollment: ' + error.message,
      };
    }
  }

  /**
   * Verify push notification MFA enrollment
   * @param factorId Factor ID
   * @param token Verification token
   * @returns Verification result
   */
  async verifyEnrollment(factorId: string, token: string): Promise<MfaVerificationResult> {
    try {
      // Get factor
      const factor = await this.mfaFactorRepository.findById(factorId);
      if (!factor || factor.type !== MfaFactorType.PUSH_NOTIFICATION) {
        return {
          success: false,
          message: 'Invalid push notification MFA factor',
        };
      }

      // In a real implementation, we would verify the token
      // For now, we'll just accept any token for demonstration purposes

      // Update factor status to active
      await this.mfaFactorRepository.update(factorId, {
        status: MfaFactorStatus.ACTIVE,
      });

      return {
        success: true,
        factorId,
        factorType: MfaFactorType.PUSH_NOTIFICATION,
        message: 'Push notification verification successful',
      };
    } catch (error: any) {
      logger.error('Failed to verify push notification MFA enrollment', { error, factorId });
      return {
        success: false,
        message: 'Failed to verify push notification MFA enrollment: ' + error.message,
      };
    }
  }

  /**
   * Generate push notification MFA challenge
   * @param factorId Factor ID
   * @returns Challenge data
   */
  async generateChallenge(factorId: string) {
    try {
      // Get factor
      const factor = await this.mfaFactorRepository.findById(factorId);
      if (!factor || factor.type !== MfaFactorType.PUSH_NOTIFICATION || !factor.deviceToken) {
        throw new NotFoundError('Invalid push notification MFA factor');
      }

      // Generate a unique challenge ID
      const challenge = uuidv4();

      // Send push notification
      await this.sendPushNotification(factor.deviceToken, {
        title: 'Authentication Required',
        body: 'Tap to approve login request',
        data: {
          type: 'authentication',
          challenge,
          factorId,
        },
      });

      return {
        challenge,
        metadata: {
          deviceToken: factor.deviceToken,
          sentAt: new Date().toISOString(),
        },
      };
    } catch (error: any) {
      logger.error('Failed to generate push notification MFA challenge', { error, factorId });
      throw error;
    }
  }

  /**
   * Verify push notification MFA challenge
   * @param challengeId Challenge ID
   * @param response Response to the challenge
   * @param metadata Additional metadata
   * @returns Verification result
   */
  async verifyChallenge(
    challengeId: string,
    response: string,
    metadata?: Record<string, any>
  ): Promise<MfaVerificationResult> {
    try {
      // Get challenge
      const challenge = await this.mfaChallengeRepository.findById(challengeId);
      if (!challenge) {
        return {
          success: false,
          message: 'Invalid challenge',
        };
      }

      // Get factor
      const factor = await this.mfaFactorRepository.findById(challenge.factorId);
      if (!factor || factor.type !== MfaFactorType.PUSH_NOTIFICATION) {
        return {
          success: false,
          message: 'Invalid push notification MFA factor',
        };
      }

      // In a real implementation, we would verify the response
      // For now, we'll just check if the response is "approved"
      if (response === 'approved') {
        return {
          success: true,
          factorId: factor.id,
          factorType: MfaFactorType.PUSH_NOTIFICATION,
          message: 'Push notification verification successful',
        };
      } else {
        return {
          success: false,
          factorId: factor.id,
          factorType: MfaFactorType.PUSH_NOTIFICATION,
          message: 'Push notification verification failed',
        };
      }
    } catch (error: any) {
      logger.error('Failed to verify push notification MFA challenge', { error, challengeId });
      return {
        success: false,
        message: 'Failed to verify push notification MFA challenge: ' + error.message,
      };
    }
  }

  /**
   * Send push notification
   * @param deviceToken Device token
   * @param notification Notification data
   */
  private async sendPushNotification(
    deviceToken: string,
    notification: {
      title: string;
      body: string;
      data: Record<string, any>;
    }
  ): Promise<void> {
    try {
      // In a real implementation, we would send a push notification
      // For now, we'll just log it
      logger.info('Sending push notification', {
        deviceToken,
        notification,
        provider: mfaConfig.pushNotification.provider,
      });

      // Simulate sending a push notification
      await new Promise(resolve => setTimeout(resolve, 100));
    } catch (error: any) {
      logger.error('Failed to send push notification', { error, deviceToken });
      throw new BadRequestError('Failed to send push notification: ' + error.message);
    }
  }

  /**
   * Generate a random verification code
   * @returns 6-digit verification code
   */
  private generateVerificationCode(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }
}
