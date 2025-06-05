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

/**
 * Certificate service for passwordless authentication
 * Implements certificate-based authentication functionality
 */
@Injectable()
export class CertificateService {
  constructor(
    private credentialRepository: PasswordlessCredentialRepository,
    private userRepository: UserRepository,
    private eventEmitter: EventEmitter
  ) {}

  /**
   * Generate a registration challenge for certificate authentication
   * @param userId User ID
   * @param options Additional options
   * @returns Registration challenge
   */
  async generateRegistrationChallenge(
    userId: string,
    options: Record<string, any> = {}
  ): Promise<Record<string, any>> {
    try {
      logger.debug('Generating certificate registration challenge', { userId });

      // Check if certificate authentication is enabled
      if (!passwordlessConfig.certificateAuth.enabled) {
        throw new BadRequestError('Certificate authentication is not enabled');
      }

      // Get user
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Generate challenge
      const challenge = this.generateChallenge();
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

      // Store challenge
      const challengeId = uuidv4();
      await this.credentialRepository.storeCertificateChallenge({
        id: challengeId,
        userId,
        challenge,
        type: 'registration',
        expiresAt,
        metadata: {
          ipAddress: options['ipAddress'],
          userAgent: options['userAgent'],
          origin: options['origin'],
        },
      });

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.CERTIFICATE_REGISTRATION_STARTED, {
        userId,
        challengeId,
        expiresAt,
        timestamp: new Date(),
      });

      return {
        id: challengeId,
        challenge,
        expiresAt,
        metadata: {
          origin: options['origin'],
        },
      };
    } catch (error) {
      logger.error('Error generating certificate registration challenge', { error, userId });
      throw error;
    }
  }

  /**
   * Verify a certificate registration response
   * @param challengeId Challenge ID
   * @param response Registration response
   * @param options Additional options
   * @returns Verification result
   */
  async verifyRegistration(
    challengeId: string,
    response: Record<string, any>,
    options: Record<string, any> = {}
  ): Promise<Record<string, any>> {
    try {
      logger.debug('Verifying certificate registration', { challengeId });

      // Find challenge
      const challenge = await this.credentialRepository.findCertificateChallengeById(challengeId);
      if (!challenge) {
        throw new NotFoundError('Certificate challenge not found');
      }

      // Check if challenge has expired
      if (challenge.expiresAt < new Date()) {
        throw new BadRequestError('Certificate challenge has expired');
      }

      // Check if challenge type is registration
      if (challenge.type !== 'registration') {
        throw new BadRequestError('Invalid challenge type');
      }

      // In a real implementation, this would verify the certificate
      // For now, we'll just extract the certificate data
      const { certificate, signature } = response;

      // Verify certificate
      if (!this.verifyCertificate(certificate, options)) {
        throw new BadRequestError('Invalid certificate');
      }

      // Verify signature
      if (!this.verifySignature(challenge.challenge, signature, certificate)) {
        throw new BadRequestError('Invalid signature');
      }

      // Extract certificate data
      const certData = this.extractCertificateData(certificate);

      // Store certificate
      const credentialId = uuidv4();
      await this.credentialRepository.storeCertificateCredential({
        id: credentialId,
        userId: challenge.userId,
        certificate,
        subject: certData.subject,
        issuer: certData.issuer,
        serialNumber: certData.serialNumber,
        validFrom: certData.validFrom,
        validTo: certData.validTo,
        fingerprint: certData.fingerprint,
        createdAt: new Date(),
        lastUsedAt: null,
        metadata: {
          ipAddress: options['ipAddress'],
          userAgent: options['userAgent'],
          origin: options['origin'],
        },
      });

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.CERTIFICATE_REGISTRATION_COMPLETED, {
        userId: challenge.userId,
        credentialId,
        timestamp: new Date(),
      });

      return {
        success: true,
        userId: challenge.userId,
        credentialId,
      };
    } catch (error) {
      logger.error('Error verifying certificate registration', { error, challengeId });
      throw error;
    }
  }

  /**
   * Generate an authentication challenge for certificate authentication
   * @param userId User ID
   * @param options Additional options
   * @returns Authentication challenge
   */
  async generateAuthenticationChallenge(
    userId: string,
    options: Record<string, any> = {}
  ): Promise<Record<string, any>> {
    try {
      logger.debug('Generating certificate authentication challenge', { userId });

      // Check if certificate authentication is enabled
      if (!passwordlessConfig.certificateAuth.enabled) {
        throw new BadRequestError('Certificate authentication is not enabled');
      }

      // Get user
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Check if user has registered certificates
      const certificates =
        await this.credentialRepository.findCertificateCredentialsByUserId(userId);
      if (certificates.length === 0) {
        throw new BadRequestError('No certificates found for user');
      }

      // Generate challenge
      const challenge = this.generateChallenge();
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

      // Store challenge
      const challengeId = uuidv4();
      await this.credentialRepository.storeCertificateChallenge({
        id: challengeId,
        userId,
        challenge,
        type: 'authentication',
        expiresAt,
        metadata: {
          ipAddress: options['ipAddress'],
          userAgent: options['userAgent'],
          origin: options['origin'],
        },
      });

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.CERTIFICATE_AUTHENTICATION_STARTED, {
        userId,
        challengeId,
        expiresAt,
        timestamp: new Date(),
      });

      return {
        id: challengeId,
        challenge,
        expiresAt,
        metadata: {
          origin: options['origin'],
        },
      };
    } catch (error) {
      logger.error('Error generating certificate authentication challenge', { error, userId });
      throw error;
    }
  }

  /**
   * Verify a certificate authentication response
   * @param challengeId Challenge ID
   * @param response Authentication response
   * @param options Additional options
   * @returns Verification result
   */
  async verifyAuthentication(
    challengeId: string,
    response: Record<string, any>,
    options: Record<string, any> = {}
  ): Promise<Record<string, any>> {
    try {
      logger.debug('Verifying certificate authentication', { challengeId });

      // Find challenge
      const challenge = await this.credentialRepository.findCertificateChallengeById(challengeId);
      if (!challenge) {
        throw new NotFoundError('Certificate challenge not found');
      }

      // Check if challenge has expired
      if (challenge.expiresAt < new Date()) {
        throw new BadRequestError('Certificate challenge has expired');
      }

      // Check if challenge type is authentication
      if (challenge.type !== 'authentication') {
        throw new BadRequestError('Invalid challenge type');
      }

      // In a real implementation, this would verify the certificate
      // For now, we'll just extract the certificate data
      const { certificate, signature } = response;

      // Verify certificate
      if (!this.verifyCertificate(certificate, options)) {
        throw new BadRequestError('Invalid certificate');
      }

      // Verify signature
      if (!this.verifySignature(challenge.challenge, signature, certificate)) {
        throw new BadRequestError('Invalid signature');
      }

      // Extract certificate data
      const certData = this.extractCertificateData(certificate);

      // Find matching credential
      const credential = await this.credentialRepository.findCertificateCredentialByFingerprint(
        certData.fingerprint
      );
      if (!credential) {
        throw new BadRequestError('Certificate not registered');
      }

      // Verify user ID
      if (credential.userId !== challenge.userId) {
        throw new BadRequestError('User ID mismatch');
      }

      // Update credential last used time
      await this.credentialRepository.updateCertificateCredential(credential.id, {
        lastUsedAt: new Date(),
      });

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.CERTIFICATE_AUTHENTICATION_COMPLETED, {
        userId: challenge.userId,
        credentialId: credential.id,
        timestamp: new Date(),
      });

      return {
        success: true,
        userId: challenge.userId,
        credentialId: credential.id,
      };
    } catch (error) {
      logger.error('Error verifying certificate authentication', { error, challengeId });
      throw error;
    }
  }

  /**
   * Delete a certificate credential
   * @param userId User ID
   * @param credentialId Credential ID
   * @returns Deletion result
   */
  async deleteCredential(userId: string, credentialId: string): Promise<boolean> {
    try {
      logger.debug('Deleting certificate credential', { userId, credentialId });

      // Find credential
      const credential =
        await this.credentialRepository.findCertificateCredentialById(credentialId);
      if (!credential) {
        throw new NotFoundError('Certificate credential not found');
      }

      // Verify user ID
      if (credential.userId !== userId) {
        throw new BadRequestError('User ID mismatch');
      }

      // Delete credential
      const result = await this.credentialRepository.deleteCertificateCredential(credentialId);

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.CREDENTIAL_DELETED, {
        userId,
        credentialId,
        type: 'certificate',
        timestamp: new Date(),
      });

      return result;
    } catch (error) {
      logger.error('Error deleting certificate credential', { error, userId, credentialId });
      throw error;
    }
  }

  /**
   * Generate a random challenge
   * @returns Base64-encoded challenge
   */
  private generateChallenge(): string {
    const buffer = crypto.randomBytes(32);
    return buffer.toString('base64');
  }

  /**
   * Verify a certificate
   * @param certificate Certificate
   * @param options Additional options
   * @returns True if certificate is valid
   */
  private verifyCertificate(_certificate: string, _options: Record<string, any> = {}): boolean {
    try {
      // In a real implementation, this would verify the certificate against trusted CAs
      // For now, we'll just return true
      return true;
    } catch (error) {
      logger.error('Error verifying certificate', { error });
      return false;
    }
  }

  /**
   * Verify a signature
   * @param challenge Challenge
   * @param signature Signature
   * @param certificate Certificate
   * @returns True if signature is valid
   */
  private verifySignature(_challenge: string, _signature: string, _certificate: string): boolean {
    try {
      // In a real implementation, this would verify the signature using the certificate's public key
      // For now, we'll just return true
      return true;
    } catch (error) {
      logger.error('Error verifying signature', { error });
      return false;
    }
  }

  /**
   * Extract data from a certificate
   * @param certificate Certificate
   * @returns Certificate data
   */
  private extractCertificateData(certificate: string): {
    subject: string;
    issuer: string;
    serialNumber: string;
    validFrom: Date;
    validTo: Date;
    fingerprint: string;
  } {
    try {
      // In a real implementation, this would extract data from the certificate
      // For now, we'll just return mock data
      return {
        subject: 'CN=Test User,O=Test Organization',
        issuer: 'CN=Test CA,O=Test Organization',
        serialNumber: '12345678',
        validFrom: new Date(),
        validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
        fingerprint: crypto.createHash('sha256').update(certificate).digest('hex'),
      };
    } catch (error) {
      logger.error('Error extracting certificate data', { error });
      throw error;
    }
  }
}
