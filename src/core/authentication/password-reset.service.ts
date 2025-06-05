import { recoveryTokenRepository } from '../../data/repositories/recovery-token.repository';
import { userRepository } from '../../data/repositories/implementations/user.repository.impl';
import { logger } from '../../infrastructure/logging/logger';
import { generateSecureToken } from '../../infrastructure/security/crypto/encryption';
import { NotFoundError, BadRequestError } from '../../utils/error-handling';
import { emitEvent } from '../events/event-bus';
import { EventType } from '../events/event-types';
import { identityService } from '../identity/identity.service';
import { RecoveryTokenType } from '../../data/models/recovery-token.model';

/**
 * Password reset service for handling password reset requests
 */
export class PasswordResetService {
  /**
   * Create a password reset token
   * @param email User email
   * @returns Password reset token and user ID
   */
  async createResetToken(email: string): Promise<{ token: string; userId: string }> {
    try {
      // Find user by email
      const user = await userRepository.findByEmail(email);
      if (!user) {
        // For security reasons, don't reveal that the email doesn't exist
        logger.info('Password reset requested for non-existent email', {
          email,
        });
        throw new NotFoundError('User not found', 'USER_NOT_FOUND');
      }

      // Invalidate any existing reset tokens
      await recoveryTokenRepository.invalidateAllForUser(user.id, RecoveryTokenType.PASSWORD_RESET);

      // Generate a new token
      const token = generateSecureToken(32);

      // Set expiration time (1 hour)
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

      // Save token
      await recoveryTokenRepository.create({
        userId: user.id,
        token,
        type: RecoveryTokenType.PASSWORD_RESET,
        expiresAt,
      });

      // Emit password reset requested event
      emitEvent(EventType.PASSWORD_RESET_REQUESTED, {
        userId: user.id,
        email,
        expiresAt,
        timestamp: new Date(),
      });

      logger.info('Password reset token created', {
        userId: user.id,
        email,
        expiresAt,
      });

      return { token, userId: user.id };
    } catch (error) {
      logger.error('Failed to create password reset token', {
        error,
        email,
      });

      throw error;
    }
  }

  /**
   * Validate a password reset token
   * @param token Password reset token
   * @returns User ID if token is valid
   */
  async validateResetToken(token: string): Promise<string> {
    try {
      // Find token
      const recoveryToken = await recoveryTokenRepository.findByToken(token);
      if (!recoveryToken) {
        throw new BadRequestError('Invalid reset token', 'INVALID_TOKEN');
      }

      // Check token type
      if (recoveryToken.type !== RecoveryTokenType.PASSWORD_RESET) {
        throw new BadRequestError('Invalid token type', 'INVALID_TOKEN_TYPE');
      }

      // Check if token is expired
      if (recoveryToken.expiresAt < new Date()) {
        throw new BadRequestError('Reset token has expired', 'TOKEN_EXPIRED');
      }

      // Check if token has already been used
      if (recoveryToken.usedAt) {
        throw new BadRequestError('Reset token has already been used', 'TOKEN_ALREADY_USED');
      }

      // Add null check for userId
      if (!recoveryToken.userId) {
        throw new BadRequestError('Invalid token data: missing user ID', 'INVALID_TOKEN_DATA');
      }

      // Get user
      const user = await userRepository.findById(recoveryToken.userId);
      if (!user) {
        throw new NotFoundError('User not found', 'USER_NOT_FOUND');
      }

      logger.info('Password reset token validated', {
        userId: user.id,
        email: user.email,
      });

      return user.id;
    } catch (error) {
      logger.error('Failed to validate password reset token', {
        error,
        token,
      });

      throw error;
    }
  }

  /**
   * Reset password with token
   * @param token Password reset token
   * @param newPassword New password
   * @returns User ID of reset user
   */
  async resetPassword(token: string, newPassword: string): Promise<string> {
    try {
      // Validate token and get user ID
      const userId = await this.validateResetToken(token);

      // Reset password
      await identityService.resetPassword(userId, newPassword);

      // Mark token as used
      const recoveryToken = await recoveryTokenRepository.findByToken(token);
      if (recoveryToken) {
        await recoveryTokenRepository.markAsUsed(recoveryToken.id);
      }

      // Get user
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found', 'USER_NOT_FOUND');
      }

      // Ensure email exists
      if (!user.email) {
        throw new BadRequestError('User email not found', 'USER_EMAIL_NOT_FOUND');
      }

      // Emit password reset event
      emitEvent(EventType.PASSWORD_RESET_COMPLETED, {
        userId,
        email: user.email,
        timestamp: new Date(),
      });

      logger.info('Password reset successfully', {
        userId,
        email: user.email,
      });

      return userId;
    } catch (error) {
      logger.error('Failed to reset password', {
        error,
        token,
      });

      throw error;
    }
  }

  /**
   * Change password for authenticated user
   * @param userId User ID
   * @param currentPassword Current password
   * @param newPassword New password
   * @returns User ID
   */
  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string
  ): Promise<string> {
    try {
      // Change password
      await identityService.changePassword(userId, currentPassword, newPassword);

      // Get user
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found', 'USER_NOT_FOUND');
      }

      // Emit password changed event
      emitEvent(EventType.PASSWORD_CHANGED, {
        userId,
        email: user.email,
        timestamp: new Date(),
      });

      logger.info('Password changed successfully', {
        userId,
        email: user.email,
      });

      return userId;
    } catch (error) {
      logger.error('Failed to change password', {
        error,
        userId,
      });

      throw error;
    }
  }
}

// Export a singleton instance
export const passwordResetService = new PasswordResetService();
