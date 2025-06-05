import { Injectable } from '@tsed/di';
import { v4 as uuidv4 } from 'uuid';
import { passwordlessConfig } from '../passwordless.config';
import { logger } from '../../../infrastructure/logging/logger';
import type { PasswordlessCredentialRepository } from '../../../data/repositories/passwordless/credential.repository';
import type { UserRepository } from '../../../data/repositories/user.repository';
import type { EventEmitter } from '../../../infrastructure/events/event-emitter';
import { PasswordlessEvent } from '../passwordless-events';
import { BadRequestError, NotFoundError } from '../../../utils/error-handling';
import crypto from 'crypto';
import { SmsOtpOptions } from '../interfaces/sms-otp-options';

/**
 * SMS OTP service for passwordless authentication
 * Implements SMS-based one-time password functionality
 */
@Injectable()
export class SmsOtpService {
  constructor(
    private credentialRepository: PasswordlessCredentialRepository,
    private userRepository: UserRepository,
    private eventEmitter: EventEmitter
  ) {}

  /**
   * Send an OTP code to the user's phone
   * @param userId User ID
   * @param phoneNumber User's phone number
   * @param options Additional options
   * @returns OTP challenge
   */
  async sendOtp(
    userId: string,
    phoneNumber: string,
    options: SmsOtpOptions = {}
  ): Promise<Record<string, any>> {
    try {
      logger.debug('Sending SMS OTP', { userId, phoneNumber });

      // Check if SMS OTP is enabled
      if (!passwordlessConfig.smsOtp.enabled) {
        throw new BadRequestError('SMS OTP authentication is not enabled');
      }

      // Get user
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Verify phone number matches user's phone number
      if (user.phoneNumber !== phoneNumber) {
        throw new BadRequestError("Phone number does not match user's phone number");
      }

      // Check if phone is verified
      if (!user.phoneVerified && passwordlessConfig.smsOtp.requireVerifiedPhone) {
        throw new BadRequestError('Phone number is not verified');
      }

      // Check rate limiting
      await this.checkRateLimiting(userId, phoneNumber);

      // Generate OTP code
      const code = this.generateOtpCode();
      const expiresAt = new Date(Date.now() + passwordlessConfig.smsOtp.codeExpiration * 1000);

      // Store OTP
      const otpId = uuidv4();
      await this.credentialRepository.storeOtp({
        id: otpId,
        userId,
        destination: phoneNumber,
        code: await this.hashOtpCode(code),
        type: 'sms',
        expiresAt,
        attempts: 0,
        maxAttempts: passwordlessConfig.smsOtp.maxAttempts,
        metadata: {
          ipAddress: options['ipAddress'],
          userAgent: options['userAgent'],
          origin: options['origin'],
          requestedAt: new Date(),
        },
      });

      // Send SMS with OTP code
      await this.sendSmsWithCode(phoneNumber, code, {
        userId,
        expiresIn: passwordlessConfig.smsOtp.codeExpiration,
      });

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.OTP_SENT, {
        userId,
        phoneNumber,
        otpId,
        expiresAt,
        type: 'sms',
        timestamp: new Date(),
      });

      return {
        id: otpId,
        expiresAt,
        phoneNumber,
        metadata: {
          origin: options['origin'],
        },
      };
    } catch (error) {
      logger.error('Error sending SMS OTP', { error, userId, phoneNumber });
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
    options: SmsOtpOptions = {}
  ): Promise<Record<string, any>> {
    try {
      logger.debug('Verifying SMS OTP', { otpId });

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

      // Check if OTP type is SMS
      if (otp.type !== 'sms') {
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
        phoneNumber: otp.destination,
        otpId,
        timestamp: new Date(),
      });

      return {
        success: true,
        userId: user.id,
        phoneNumber: otp.destination,
      };
    } catch (error) {
      logger.error('Error verifying SMS OTP', { error, otpId });
      throw error;
    }
  }

  /**
   * Generate a secure OTP code
   * @returns OTP code
   */
  private generateOtpCode(): string {
    const codeLength = passwordlessConfig.smsOtp.codeLength;
    const codeType = passwordlessConfig.smsOtp.codeType;

    if (codeType === 'numeric') {
      // Generate numeric code
      const min = Math.pow(10, codeLength - 1);
      const max = Math.pow(10, codeLength) - 1;
      return Math.floor(min + Math.random() * (max - min + 1)).toString();
    } else {
      // Generate alphanumeric code
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      let code = '';
      const randomBytes = crypto.randomBytes(codeLength);
      for (let i = 0; i < codeLength; i++) {
        // Ensure we have a valid number even if randomBytes[i] is undefined
        const byteValue = randomBytes[i] ?? 0;
        code += chars[byteValue % chars.length];
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

      // Ensure code is a string
      const safeCode = code || '';

      crypto.scrypt(safeCode, salt, 64, (err, derivedKey) => {
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
      const [salt, key] = hash.split(':');
      if (!salt || !key) {
        reject(new Error('Invalid hash format'));
        return;
      }

      // Ensure code is a string
      const safeCode = code || '';

      crypto.scrypt(safeCode, salt, 64, (err, derivedKey) => {
        if (err) reject(err);
        resolve(key === derivedKey.toString('hex'));
      });
    });
  }

  /**
   * Send SMS with OTP code
   * @param phoneNumber Phone number
   * @param code OTP code
   * @param options Additional options
   */
  private async sendSmsWithCode(
    phoneNumber: string,
    code: string,
    options: SmsOtpOptions = {}
  ): Promise<void> {
    try {
      // In a real implementation, this would send an SMS using a provider like Twilio or AWS SNS
      // For now, we'll just log the code
      logger.info(`[MOCK SMS] Sending OTP code ${code} to ${phoneNumber}`, { options });

      // Determine which SMS provider to use
      const providers = passwordlessConfig.smsOtp.providers || ['twilio'];
      const provider = providers[0] || 'twilio'; // Use the first provider in the list or default to twilio

      // Send SMS based on provider
      switch (provider) {
        case 'twilio':
          // In a real implementation, this would use Twilio's API
          logger.info(`[MOCK TWILIO] Sending OTP code ${code} to ${phoneNumber}`);
          break;
        case 'aws-sns':
          // In a real implementation, this would use AWS SNS
          logger.info(`[MOCK AWS SNS] Sending OTP code ${code} to ${phoneNumber}`);
          break;
        case 'custom':
          // In a real implementation, this would use a custom SMS provider
          logger.info(`[MOCK CUSTOM] Sending OTP code ${code} to ${phoneNumber}`);
          break;
        default:
          logger.warn(`Unknown SMS provider: ${provider}`);
          break;
      }

      return;
    } catch (error) {
      logger.error('Error sending SMS with code', { error, phoneNumber });
      throw error;
    }
  }

  /**
   * Check rate limiting for OTP generation
   * @param userId User ID
   * @param phoneNumber Phone number
   * @throws BadRequestError if rate limit exceeded
   */
  private async checkRateLimiting(userId: string, phoneNumber: string): Promise<void> {
    try {
      // In a real implementation, this would check a rate limiting service
      // For now, we'll just return
      return;
    } catch (error) {
      logger.error('Error checking rate limiting', { error, userId, phoneNumber });
      throw error;
    }
  }
}
