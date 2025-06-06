import { Injectable } from '@tsed/di';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from '@simplewebauthn/types';
import type { MfaFactorRepository } from '../../../data/repositories/mfa-factor.repository';
import type { MfaChallengeRepository } from '../../../data/repositories/mfa-challenge.repository';
import type { UserRepository } from '../../../data/repositories/user.repository';
import {
  MfaFactorType,
  MfaFactorStatus,
  type MfaEnrollmentResult,
  type MfaVerificationResult,
} from '../mfa-factor-types';
import {
  WebAuthnAuthenticatorData,
  WebAuthnVerificationError,
  WebAuthnErrorType,
} from './webauthn.types';
import { mfaConfig } from '../../../config/mfa-config';
import { logger } from '../../../infrastructure/logging/logger';
import { BadRequestError, NotFoundError } from '../../../utils/error-handling';

@Injectable()
export class WebAuthnService {
  constructor(
    private mfaFactorRepository: MfaFactorRepository,
    private mfaChallengeRepository: MfaChallengeRepository,
    private userRepository: UserRepository
  ) {}

  /**
   * Converts a string to a Uint8Array for WebAuthn compatibility
   * @param str String to convert
   * @returns Uint8Array representation of the string
   */
  private stringToBuffer(str: string): Uint8Array {
    try {
      if (!str) {
        throw new Error('Input string cannot be empty');
      }
      return new TextEncoder().encode(str);
    } catch (error) {
      logger.error('Failed to convert string to buffer', { error, str });
      throw new Error('Failed to process user ID');
    }
  }

  /**
   * Start WebAuthn enrollment process
   * @param userId User ID
   * @param factorName Name for the factor
   * @param factorData Additional factor data
   * @returns Enrollment result with registration options
   */
  async startEnrollment(
    userId: string,
    factorName: string,
    _factorData?: Record<string, any>
  ): Promise<MfaEnrollmentResult> {
    try {
      // Get user
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Generate registration options
      const rpName = mfaConfig.webAuthn.rpName;
      const rpID = mfaConfig.webAuthn.rpID || '';

      // Convert userId to Uint8Array for WebAuthn compatibility
      const userIdBuffer = this.stringToBuffer(userId);

      // Ensure we have a valid username
      const userName = user.username || user.email || userId;
      if (!userName) {
        throw new BadRequestError('No valid identifier found for user');
      }

      const registrationOptions = await generateRegistrationOptions({
        rpName,
        rpID,
        userID: userIdBuffer,
        userName, // Now guaranteed to be a string
        userDisplayName: user.email || userName,
        attestationType: mfaConfig.webAuthn.attestation as 'direct' | 'none' | 'enterprise',
        authenticatorSelection: {
          userVerification: mfaConfig.webAuthn.userVerification as
            | 'required'
            | 'preferred'
            | 'discouraged',
        },
        timeout: mfaConfig.webAuthn.timeout,
      });

      // Create factor record
      const factor = await this.mfaFactorRepository.create({
        userId,
        type: MfaFactorType.WEBAUTHN,
        name: factorName,
        status: MfaFactorStatus.PENDING,
        metadata: {
          challenge: registrationOptions.challenge,
          rpID: registrationOptions.rp.id,
          origin: mfaConfig.webAuthn.origin || '',
        },
      });

      return {
        success: true,
        factorId: factor.id,
        factorType: MfaFactorType.WEBAUTHN,
        activationData: registrationOptions,
        message: 'WebAuthn registration options generated',
      };
    } catch (error: any) {
      logger.error('Failed to start WebAuthn enrollment', { error, userId });
      return {
        success: false,
        message: 'Failed to start WebAuthn enrollment: ' + error.message,
      };
    }
  }

  /**
   * Verify WebAuthn enrollment by checking the attestation response
   * @param factorId Factor ID
   * @param attestationResponse WebAuthn attestation response
   * @returns Verification result
   */
  async verifyEnrollment(
    factorId: string,
    attestationResponse: RegistrationResponseJSON
  ): Promise<MfaVerificationResult> {
    try {
      // Get factor
      const factor = await this.mfaFactorRepository.findById(factorId);
      if (!factor || factor.type !== MfaFactorType.WEBAUTHN || !factor.metadata) {
        return {
          success: false,
          message: 'Invalid WebAuthn factor',
        };
      }

      // Extract expected values from factor metadata
      const expectedChallenge = factor.metadata['challenge'];
      const expectedOrigin = factor.metadata['origin'] || mfaConfig.webAuthn.origin;
      const expectedRPID = factor.metadata['rpID'] || mfaConfig.webAuthn.rpID;

      // Verify attestation
      const verification = await verifyRegistrationResponse({
        response: attestationResponse,
        expectedChallenge,
        expectedOrigin,
        expectedRPID,
      });

      if (verification.verified) {
        // Extract credential data from the verification result
        // Use type assertion to access the properties we need
        const registrationInfo = verification.registrationInfo as any;
        const credentialID = registrationInfo.credentialID;
        const credentialPublicKey = registrationInfo.credentialPublicKey;
        const counter = registrationInfo.counter || 0;

        // Update factor with credential data
        await this.mfaFactorRepository.update(factorId, {
          credentialId: Buffer.from(credentialID).toString('base64url'),
          metadata: {
            ...factor.metadata,
            credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64url'),
            counter: counter || 0,
            credentialDeviceType: 'security-key', // Default to security-key
            credentialBackedUp: false, // Default to false
          },
        });

        return {
          success: true,
          factorId,
          factorType: MfaFactorType.WEBAUTHN,
          message: 'WebAuthn registration successful',
        };
      } else {
        return {
          success: false,
          factorId,
          factorType: MfaFactorType.WEBAUTHN,
          message: 'WebAuthn registration verification failed',
        };
      }
    } catch (error: any) {
      logger.error('Failed to verify WebAuthn enrollment', { error, factorId });
      return {
        success: false,
        message: 'Failed to verify WebAuthn enrollment: ' + error.message,
      };
    }
  }

  /**
   * Generate WebAuthn challenge for authentication
   * @param factorId Factor ID
   * @returns Challenge data
   */
  async generateChallenge(factorId: string) {
    try {
      // Get factor
      const factor = await this.mfaFactorRepository.findById(factorId);
      if (!factor || factor.type !== MfaFactorType.WEBAUTHN || !factor.metadata) {
        throw new NotFoundError('Invalid WebAuthn factor');
      }

      // Extract credential data
      const credentialID = factor.credentialId;
      if (!credentialID) {
        throw new BadRequestError('WebAuthn factor is not properly configured');
      }

      // Generate authentication options
      const authenticationOptions = await generateAuthenticationOptions({
        rpID: factor.metadata['rpID'] || mfaConfig.webAuthn.rpID,
        userVerification: mfaConfig.webAuthn.userVerification as
          | 'required'
          | 'preferred'
          | 'discouraged',
        timeout: mfaConfig.webAuthn.timeout,
        allowCredentials: [
          {
            id: credentialID,
          },
        ],
      });

      return {
        challenge: authenticationOptions.challenge,
        metadata: {
          options: authenticationOptions,
          rpID: factor.metadata['rpID'] || mfaConfig.webAuthn.rpID,
          origin: factor.metadata['origin'] || mfaConfig.webAuthn.origin,
        },
      };
    } catch (error: any) {
      logger.error('Failed to generate WebAuthn challenge', { error, factorId });
      throw error;
    }
  }

  /**
   * Verify WebAuthn challenge response
   * @param challengeId Challenge ID
   * @param assertionResponse WebAuthn assertion response
   * @param metadata Additional metadata
   * @returns Verification result
   */
  async verifyChallenge(
    challengeId: string,
    assertionResponse: AuthenticationResponseJSON,
    _metadata?: Record<string, any>
  ): Promise<MfaVerificationResult> {
    try {
      // Get challenge
      const challenge = await this.mfaChallengeRepository.findById(challengeId);
      if (!challenge || !challenge.metadata) {
        logger.warn('Invalid challenge for WebAuthn verification', { challengeId });
        throw new WebAuthnVerificationError('Invalid challenge', {
          type: WebAuthnErrorType.INVALID_CHALLENGE,
          challengeId,
        });
      }

      // Get factor
      const factor = await this.mfaFactorRepository.findById(challenge.factorId);
      if (!factor || factor.type !== MfaFactorType.WEBAUTHN || !factor.metadata) {
        logger.warn('Invalid WebAuthn factor for verification', {
          challengeId,
          factorId: challenge.factorId,
        });
        throw new WebAuthnVerificationError('Invalid WebAuthn factor', {
          type: WebAuthnErrorType.INVALID_FACTOR,
          factorId: challenge.factorId,
        });
      }

      // Extract expected values
      const expectedChallenge = challenge.challenge;
      const expectedOrigin = factor.metadata['origin'] || mfaConfig.webAuthn.origin;
      const expectedRPID = factor.metadata['rpID'] || mfaConfig.webAuthn.rpID;
      const credentialPublicKey = Buffer.from(factor.metadata['credentialPublicKey'], 'base64url');
      const expectedCounter = factor.metadata['counter'] || 0;

      // Prepare authenticator data with proper typing
      const authenticator: WebAuthnAuthenticatorData = {
        credentialID: Buffer.from(factor.credentialId!, 'base64url'),
        credentialPublicKey: credentialPublicKey,
        counter: expectedCounter,
      };

      // Verify assertion
      // Use type assertion to work around type issues with the authenticator parameter
      const verification = await verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge,
        expectedOrigin,
        expectedRPID,
        authenticator,
        ...(mfaConfig.webAuthn.userVerification === 'required'
          ? { requireUserVerification: true }
          : {}),
      } as any);

      if (verification.verified) {
        const newCounter = verification.authenticationInfo.newCounter;

        // Verify counter to prevent replay attacks
        if (newCounter <= expectedCounter) {
          const details = {
            factorId: factor.id,
            expectedCounter,
            receivedCounter: newCounter,
            type: WebAuthnErrorType.REPLAY_ATTACK,
          };

          logger.warn('Possible replay attack detected', details);

          throw new WebAuthnVerificationError(
            'Authentication failed: Invalid counter value',
            details
          );
        }

        // Update factor with new counter value
        await this.mfaFactorRepository.update(factor.id, {
          metadata: {
            ...factor.metadata,
            counter: newCounter,
          },
        });

        return {
          success: true,
          factorId: factor.id,
          factorType: MfaFactorType.WEBAUTHN,
          message: 'WebAuthn authentication successful',
        };
      } else {
        return {
          success: false,
          factorId: factor.id,
          factorType: MfaFactorType.WEBAUTHN,
          message: 'WebAuthn authentication failed',
        };
      }
    } catch (error: any) {
      // Handle WebAuthnVerificationError specifically
      if (error instanceof WebAuthnVerificationError) {
        logger.warn('WebAuthn verification failed', {
          error: error.message,
          details: error.details,
          challengeId,
        });

        return {
          success: false,
          message: error.message,
          factorId: error.details['factorId'],
          factorType: MfaFactorType.WEBAUTHN,
        };
      }

      // Handle other errors
      logger.error('Failed to verify WebAuthn challenge', {
        error,
        challengeId,
        errorMessage: error.message,
        stack: error.stack,
      });

      return {
        success: false,
        message: 'Failed to verify WebAuthn challenge: ' + error.message,
      };
    }
  }
}
