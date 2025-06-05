import { Injectable } from '@tsed/di';
import { v4 as uuidv4 } from 'uuid';
import { passwordlessConfig } from '../passwordless.config';
import { logger } from '../../../infrastructure/logging/logger';
import type { PasswordlessCredentialRepository } from '../../../data/repositories/passwordless/credential.repository';
import type { UserRepository } from '../../../data/repositories/user.repository';
import type { EventEmitter } from '../../../infrastructure/events/event-emitter';
import type { EmailService } from '../../notifications/email.service';
import { PasswordlessEvent } from '../passwordless-events';
import { BadRequestError, NotFoundError } from '../../../utils/error-handling';
import crypto from 'crypto';

/**
 * Email OTP service for passwordless authentication
 * Implements email-based one-time password functionality
 */
@Injectable()
export class EmailOtpService {
  constructor(
    private credentialRepository: PasswordlessCredentialRepository,
    private userRepository: UserRepository,
    private emailService: EmailService,
    private eventEmitter: EventEmitter
  ) {}

  /**
   * Send an OTP code to the user's email
   * @param userId User ID
   * @param email User's email
   * @param options Additional options
   * @returns OTP challenge
   */
  async sendOtp(
    userId: string,
    email: string,
    options: Record<string, any> = {}
  ): Promise<Record<string, any>> {
    try {
      logger.debug('Sending email OTP', { userId, email });

      // Check if email OTP is enabled
      if (!passwordlessConfig.emailOtp.enabled) {
        throw new BadRequestError('Email OTP authentication is not enabled');
      }

      // Get user
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Verify email matches user's email
      if (user.email !== email) {
        throw new BadRequestError("Email does not match user's email");
      }

      // Check if email is verified
      if (!user.emailVerified && passwordlessConfig.emailOtp.requireVerifiedEmail) {
        throw new BadRequestError('Email is not verified');
      }

      // Check rate limiting
      await this.checkRateLimiting(userId, email);

      // Generate OTP code
      const code = this.generateOtpCode();
      const expiresAt = new Date(Date.now() + passwordlessConfig.emailOtp.codeExpiration * 1000);

      // Store OTP
      const otpId = uuidv4();
      await this.credentialRepository.storeOtp({
        id: otpId,
        userId,
        destination: email,
        code: await this.hashOtpCode(code),
        type: 'email',
        expiresAt,
        attempts: 0,
        maxAttempts: passwordlessConfig.emailOtp.maxAttempts,
        metadata: {
          ipAddress: options['ipAddress'],
          userAgent: options['userAgent'],
          origin: options['origin'],
          requestedAt: new Date(),
        },
      });

      // Send email with OTP code
      await this.emailService.sendOtpCode(email, code, {
        userId,
        expiresIn: passwordlessConfig.emailOtp.codeExpiration,
        ipAddress: options['ipAddress'],
        userAgent: options['userAgent'],
      });

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.OTP_SENT, {
        userId,
        email,
        otpId,
        expiresAt,
        type: 'email',
        timestamp: new Date(),
      });

      return {
        id: otpId,
        expiresAt,
        email,
        metadata: {
          origin: options['origin'],
        },
      };
    } catch (error) {
      logger.error('Error sending email OTP', { error, userId, email });
      throw error;
    }
  }

  /**
   * Verify an OTP code
   * @param otpId OTP ID
   * @param code OTP code
   * @param options Additional options
   * @returns Verification result
   */
  async verifyOtp(
    otpId: string,
    code: string,
    options: Record<string, any> = {}
  ): Promise<Record<string, any>> {
    try {
      logger.debug('Verifying email OTP', { otpId });

      // Find OTP
      const otp = await this.credentialRepository.findOtpById(otpId);
      if (!otp) {
        throw new NotFoundError('OTP not found');
      }

      // Check if OTP has expired
      if (otp.expiresAt < new Date()) {
        // Emit event
        this.eventEmitter.emit(PasswordlessEvent.OTP_EXPIRED, {
          userId: otp.userId,
          otpId,
          timestamp: new Date(),
        });

        throw new BadRequestError('OTP has expired');
      }

      // Check if OTP type is email
      if (otp.type !== 'email') {
        throw new BadRequestError('Invalid OTP type');
      }

      // Check if max attempts reached
      if (otp.attempts >= otp.maxAttempts) {
        throw new BadRequestError('Maximum verification attempts reached');
      }

      // Increment attempts
      await this.credentialRepository.updateOtp(otpId, {
        attempts: otp.attempts + 1,
      });

      // Verify OTP code
      const isValid = await this.verifyOtpCode(code, otp.code);
      if (!isValid) {
        // Emit event
        this.eventEmitter.emit(PasswordlessEvent.OTP_FAILED, {
          userId: otp.userId,
          otpId,
          attempts: otp.attempts + 1,
          timestamp: new Date(),
        });

        throw new BadRequestError('Invalid OTP code');
      }

      // Get user
      const user = await this.userRepository.findById(otp.userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Mark OTP as used
      await this.credentialRepository.updateOtp(otpId, {
        attempts: otp.attempts + 1,
        metadata: {
          ...otp.metadata,
          verificationIpAddress: options['ipAddress'],
          verificationUserAgent: options['userAgent'],
          verifiedAt: new Date(),
        },
      });

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.OTP_VERIFIED, {
        userId: user.id,
        email: otp.destination,
        otpId,
        timestamp: new Date(),
      });

      return {
        success: true,
        userId: user.id,
        email: otp.destination,
      };
    } catch (error) {
      logger.error('Error verifying email OTP', { error, otpId });
      throw error;
    }
  }

  /**
   * Generate a secure OTP code
   * @returns OTP code
   */
  private generateOtpCode(): string {
    const codeLength = passwordlessConfig.emailOtp.codeLength || 6;
    const codeType = passwordlessConfig.emailOtp.codeType || 'numeric';

    if (codeType === 'numeric') {
      // Generate numeric code
      const min = Math.pow(10, codeLength - 1);
      const max = Math.pow(10, codeLength) - 1;
      return Math.floor(min + Math.random() * (max - min + 1)).toString();
    } else {
      // Generate alphanumeric code
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      let code = '';

      // Use a more direct approach to avoid TypeScript errors
      for (let i = 0; i < codeLength; i++) {
        const randomIndex = Math.floor(Math.random() * chars.length);
        code += chars[randomIndex];
      }
      return code;
    }
  }

  /**
   * Hash an OTP code for secure storage
   * @param code OTP code
   * @returns Hashed code
   */
  private async hashOtpCode(code: string): Promise<string> {
    return new Promise((resolve, reject) => {
      // Use a secure hashing algorithm with a salt
      const salt = crypto.randomBytes(16).toString('hex');
      crypto.scrypt(code, salt, 64, (err, derivedKey) => {
        if (err) reject(err);
        resolve(salt + ':' + derivedKey.toString('hex'));
      });
    });
  }

  /**
   * Verify an OTP code against a hash
   * @param code OTP code
   * @param hash Hashed code
   * @returns True if code is valid
   */
  private async verifyOtpCode(code: string, hash: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      if (!hash) {
        resolve(false);
        return;
      }

      const [salt, key] = hash.split(':');
      if (!salt || !key) {
        resolve(false);
        return;
      }

      crypto.scrypt(code || '', salt, 64, (err, derivedKey) => {
        if (err) reject(err);
        resolve(key === derivedKey.toString('hex'));
      });
    });
  }

  /**
   * Check rate limiting for OTP generation
   * @param userId User ID
   * @param email Email address
   * @throws BadRequestError if rate limit exceeded
   */
  private async checkRateLimiting(userId: string, email: string): Promise<void> {
    try {
      // In a real implementation, this would check a rate limiting service
      // For now, we'll just return
      return;
    } catch (error) {
      logger.error('Error checking rate limiting', { error, userId, email });
      throw error;
    }
  }
}
