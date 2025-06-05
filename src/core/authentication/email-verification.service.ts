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
 * Email verification service for handling email verification
 */
export class EmailVerificationService {
  /**
   * Create an email verification token
   * @param userId User ID
   * @returns Verification token
   */
  async createVerificationToken(userId: string): Promise<string> {
    try {
      // Check if user exists
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found', 'USER_NOT_FOUND');
      }

      // Check if user email is already verified
      if (user.emailVerified) {
        throw new BadRequestError('Email is already verified', 'EMAIL_ALREADY_VERIFIED');
      }

      // Invalidate any existing verification tokens
      await recoveryTokenRepository.invalidateAllForUser(
        userId,
        RecoveryTokenType.EMAIL_VERIFICATION
      );

      // Generate a new token
      const token = generateSecureToken(32);

      // Set expiration time (24 hours)
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

      // Save token
      await recoveryTokenRepository.create({
        userId,
        token,
        type: RecoveryTokenType.EMAIL_VERIFICATION,
        expiresAt,
      });

      // Emit token created event
      emitEvent(EventType.EMAIL_VERIFICATION_REQUESTED, {
        userId,
        token,
        expiresAt,
        timestamp: new Date(),
      });

      logger.info('Email verification token created', {
        userId,
        expiresAt,
      });

      return token;
    } catch (error) {
      logger.error('Failed to create email verification token', {
        error,
        userId,
      });

      throw error;
    }
  }

  /**
   * Verify email with token
   * @param token Verification token
   * @returns User ID of verified user
   */
  async verifyEmail(token: string): Promise<string> {
    try {
      // Find token
      const recoveryToken = await recoveryTokenRepository.findByToken(token);
      if (!recoveryToken) {
        throw new BadRequestError('Invalid verification token', 'INVALID_TOKEN');
      }

      // Check token type
      if (recoveryToken.type !== RecoveryTokenType.EMAIL_VERIFICATION) {
        throw new BadRequestError('Invalid token type', 'INVALID_TOKEN_TYPE');
      }

      // Check if token is expired
      if (recoveryToken.expiresAt < new Date()) {
        throw new BadRequestError('Verification token has expired', 'TOKEN_EXPIRED');
      }

      // Check if token has already been used
      if (recoveryToken.usedAt) {
        throw new BadRequestError('Verification token has already been used', 'TOKEN_ALREADY_USED');
      }

      // Get user
      const user = await userRepository.findById(recoveryToken.userId || '');
      if (!user) {
        throw new NotFoundError('User not found', 'USER_NOT_FOUND');
      }

      // Check if email is already verified
      if (user.emailVerified) {
        // Mark token as used
        await recoveryTokenRepository.markAsUsed(recoveryToken.id);
        throw new BadRequestError('Email is already verified', 'EMAIL_ALREADY_VERIFIED');
      }

      // Verify email
      await identityService.verifyEmail(user.id);

      // Mark token as used
      await recoveryTokenRepository.markAsUsed(recoveryToken.id);

      // Emit email verified event
      emitEvent(EventType.EMAIL_VERIFIED, {
        userId: user.id,
        email: user.email,
        timestamp: new Date(),
      });

      logger.info('Email verified successfully', {
        userId: user.id,
        email: user.email,
      });

      return user.id;
    } catch (error) {
      logger.error('Failed to verify email', {
        error,
        token,
      });

      throw error;
    }
  }

  /**
   * Resend verification email
   * @param userId User ID
   * @returns New verification token
   */
  async resendVerificationEmail(userId: string): Promise<string> {
    try {
      // Check if user exists
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found', 'USER_NOT_FOUND');
      }

      // Check if user email is already verified
      if (user.emailVerified) {
        throw new BadRequestError('Email is already verified', 'EMAIL_ALREADY_VERIFIED');
      }

      // Create new verification token
      const token = await this.createVerificationToken(userId);

      // Emit resend event
      emitEvent(EventType.EMAIL_VERIFICATION_RESENT, {
        userId,
        email: user.email,
        timestamp: new Date(),
      });

      logger.info('Verification email resent', {
        userId,
        email: user.email,
      });

      return token;
    } catch (error) {
      logger.error('Failed to resend verification email', {
        error,
        userId,
      });

      throw error;
    }
  }

  /**
   * Check if a user's email is verified
   * @param userId User ID
   * @returns Whether the email is verified
   */
  async isEmailVerified(userId: string): Promise<boolean> {
    try {
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found', 'USER_NOT_FOUND');
      }

      return !!user.emailVerified;
    } catch (error) {
      logger.error('Failed to check email verification status', {
        error,
        userId,
      });

      throw error;
    }
  }
}

// Export a singleton instance
export const emailVerificationService = new EmailVerificationService();
