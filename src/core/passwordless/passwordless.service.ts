import { Injectable } from '@tsed/di';
import type { PasswordlessCredentialRepository } from '../../data/repositories/passwordless/credential.repository';
import type { PasswordlessSessionRepository } from '../../data/repositories/passwordless/session.repository';
import type { UserRepository } from '../../data/repositories/user.repository';
import type { EventEmitter } from '../../infrastructure/events/event-emitter';
import { logger } from '../../infrastructure/logging/logger';
import { BadRequestError, NotFoundError, UnauthorizedError } from '../../utils/error-handling';
import type { AuditLogService } from '../audit/audit-log.service';
import { PasswordlessEvent } from './passwordless-events';
import { passwordlessConfig } from './passwordless.config';
import { MagicLinkService } from './services/magic-link.service';
import { WebAuthnService } from './services/webauthn.service';
import { Challenge, Credential, User, VerificationResult } from './types';

/**
 * Passwordless authentication service
 * Coordinates various passwordless authentication methods
 */
@Injectable()
export class PasswordlessService {
  constructor(
    private webAuthnService: WebAuthnService,
    private magicLinkService: MagicLinkService,
    private userRepository: UserRepository,
    private passwordlessCredentialRepository: PasswordlessCredentialRepository,
    private passwordlessSessionRepository: PasswordlessSessionRepository,
    private auditLogService: AuditLogService,
    private eventEmitter: EventEmitter
  ) {}

  /**
   * Start passwordless authentication flow
   * @param method Passwordless method
   * @param identifier User identifier (email, phone, etc.)
   * @param options Additional options
   * @returns Authentication challenge
   */
  async startAuthentication(
    method: string,
    identifier: string,
    options: Record<string, any> = {}
  ): Promise<Record<string, any>> {
    try {
      logger.debug('Starting passwordless authentication', { method, identifier });

      // Validate method
      this.validateMethod(method);

      // Find or create user based on identifier
      const user = await this.findOrCreateUser(identifier, method);

      // Generate authentication challenge based on method
      let challenge: Challenge;

      switch (method) {
        case 'webauthn':
          challenge = (await this.webAuthnService.generateAuthenticationChallenge(
            user.id,
            options
          )) as Challenge;
          break;
        case 'magic-link':
          challenge = (await this.magicLinkService.sendMagicLink(
            user.id,
            identifier,
            options
          )) as Challenge;
          break;
        default:
          throw new BadRequestError(`Unsupported passwordless method: ${method}`);
      }

      // Create authentication session
      const session = await this.passwordlessSessionRepository.create({
        userId: user.id,
        method,
        identifier,
        challengeId: challenge.id,
        expiresAt: challenge.expiresAt,
        metadata: {
          ...options,
          ...challenge.metadata,
        },
      });

      // Log authentication attempt
      await this.auditLogService.create({
        userId: user.id,
        action: 'PASSWORDLESS_AUTHENTICATION_STARTED',
        entityType: 'PASSWORDLESS_SESSION',
        entityId: session.id,
        metadata: {
          method,
          identifier,
          ipAddress: options['ipAddress'],
          userAgent: options['userAgent'],
        },
      });

      // Emit authentication started event
      this.eventEmitter.emit(PasswordlessEvent.AUTHENTICATION_STARTED, {
        userId: user.id,
        method,
        identifier,
        sessionId: session.id,
        timestamp: new Date(),
      });

      return {
        sessionId: session.id,
        challengeId: challenge.id,
        expiresAt: challenge.expiresAt,
        userId: user.id,
        ...challenge.clientData,
      };
    } catch (error) {
      logger.error('Error starting passwordless authentication', { error, method, identifier });
      throw error;
    }
  }

  /**
   * Complete passwordless authentication flow
   * @param sessionId Authentication session ID
   * @param response Authentication response
   * @param options Additional options
   * @returns Authentication result with user and token
   */
  async completeAuthentication(
    sessionId: string,
    response: Record<string, any>,
    options: Record<string, any> = {}
  ): Promise<Record<string, any>> {
    try {
      logger.debug('Completing passwordless authentication', { sessionId });

      // Find authentication session
      const session = await this.passwordlessSessionRepository.findById(sessionId);
      if (!session) {
        throw new NotFoundError('Authentication session not found');
      }

      // Check if session has expired
      if (session.expiresAt < new Date()) {
        throw new BadRequestError('Authentication session has expired');
      }

      // Check if session has been completed
      if (session.completedAt) {
        throw new BadRequestError('Authentication session has already been completed');
      }

      // Get user
      const user = await this.userRepository.findById(session.userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Verify authentication response based on method
      let verificationResult: VerificationResult;

      switch (session.method) {
        case 'webauthn':
          verificationResult = (await this.webAuthnService.verifyAuthentication(
            session.challengeId,
            response,
            session.metadata
          )) as VerificationResult;
          break;
        case 'magic-link':
          verificationResult = (await this.magicLinkService.verifyMagicLink(
            session.challengeId,
            response['token'],
            session.metadata
          )) as VerificationResult;
          break;
        default:
          throw new BadRequestError(`Unsupported passwordless method: ${session.method}`);
      }

      if (!verificationResult.success) {
        // Log failed authentication
        await this.auditLogService.create({
          userId: user.id,
          action: 'PASSWORDLESS_AUTHENTICATION_FAILED',
          entityType: 'PASSWORDLESS_SESSION',
          entityId: session.id,
          metadata: {
            method: session.method,
            identifier: session.identifier,
            reason: verificationResult.reason,
            ipAddress: options['ipAddress'],
            userAgent: options['userAgent'],
          },
        });

        // Emit authentication failed event
        this.eventEmitter.emit(PasswordlessEvent.AUTHENTICATION_FAILED, {
          userId: user.id,
          method: session.method,
          identifier: session.identifier,
          sessionId: session.id,
          reason: verificationResult.reason,
          timestamp: new Date(),
        });

        throw new UnauthorizedError(verificationResult.reason || 'Authentication failed');
      }

      // Update session as completed
      await this.passwordlessSessionRepository.update(sessionId, {
        completedAt: new Date(),
        metadata: {
          ...session.metadata,
          verificationResult,
        },
      });

      // Update user's last login time
      await this.userRepository.update(user.id, {
        lastLoginAt: new Date(),
      });

      // Generate authentication token
      const token = this.generateAuthToken(user.id, session.method);

      // Log successful authentication
      await this.auditLogService.create({
        userId: user.id,
        action: 'PASSWORDLESS_AUTHENTICATION_SUCCEEDED',
        entityType: 'PASSWORDLESS_SESSION',
        entityId: session.id,
        metadata: {
          method: session.method,
          identifier: session.identifier,
          ipAddress: options['ipAddress'],
          userAgent: options['userAgent'],
        },
      });

      // Emit authentication succeeded event
      this.eventEmitter.emit(PasswordlessEvent.AUTHENTICATION_SUCCEEDED, {
        userId: user.id,
        method: session.method,
        identifier: session.identifier,
        sessionId: session.id,
        timestamp: new Date(),
      });

      return {
        success: true,
        user: this.sanitizeUser(user),
        token,
        expiresAt: new Date(Date.now() + passwordlessConfig.session.duration * 1000),
      };
    } catch (error) {
      logger.error('Error completing passwordless authentication', { error, sessionId });
      throw error;
    }
  }

  /**
   * Register a new passwordless credential
   * @param userId User ID
   * @param method Passwordless method
   * @param identifier User identifier (email, phone, etc.)
   * @param options Additional options
   * @returns Registration challenge
   */
  async startRegistration(
    userId: string,
    method: string,
    identifier: string,
    options: Record<string, any> = {}
  ): Promise<Record<string, any>> {
    try {
      logger.debug('Starting passwordless credential registration', { userId, method, identifier });

      // Validate method
      this.validateMethod(method);

      // Check if user exists
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Generate registration challenge based on method
      let challenge: Challenge;

      switch (method) {
        case 'webauthn':
          challenge = (await this.webAuthnService.generateRegistrationChallenge(
            userId,
            options
          )) as Challenge;
          break;
        case 'magic-link':
          // Magic link doesn't require registration, just send a magic link
          challenge = (await this.magicLinkService.sendMagicLink(
            userId,
            identifier,
            options
          )) as Challenge;
          break;
        default:
          throw new BadRequestError(`Unsupported passwordless method: ${method}`);
      }

      // Create registration session
      const session = await this.passwordlessSessionRepository.create({
        userId,
        method,
        identifier,
        challengeId: challenge.id,
        expiresAt: challenge.expiresAt,
        isRegistration: true,
        metadata: {
          ...options,
          ...challenge.metadata,
        },
      });

      // Log registration attempt
      await this.auditLogService.create({
        userId,
        action: 'PASSWORDLESS_REGISTRATION_STARTED',
        entityType: 'PASSWORDLESS_SESSION',
        entityId: session.id,
        metadata: {
          method,
          identifier,
          ipAddress: options['ipAddress'],
          userAgent: options['userAgent'],
        },
      });

      // Emit registration started event
      this.eventEmitter.emit(PasswordlessEvent.REGISTRATION_STARTED, {
        userId,
        method,
        identifier,
        sessionId: session.id,
        timestamp: new Date(),
      });

      return {
        sessionId: session.id,
        challengeId: challenge.id,
        expiresAt: challenge.expiresAt,
        ...challenge.clientData,
      };
    } catch (error) {
      logger.error('Error starting passwordless registration', {
        error,
        userId,
        method,
        identifier,
      });
      throw error;
    }
  }

  /**
   * Complete passwordless credential registration
   * @param sessionId Registration session ID
   * @param response Registration response
   * @param options Additional options
   * @returns Registration result
   */
  async completeRegistration(
    sessionId: string,
    response: Record<string, any>,
    options: Record<string, any> = {}
  ): Promise<Record<string, any>> {
    try {
      logger.debug('Completing passwordless credential registration', { sessionId });

      // Find registration session
      const session = await this.passwordlessSessionRepository.findById(sessionId);
      if (!session) {
        throw new NotFoundError('Registration session not found');
      }

      // Check if session has expired
      if (session.expiresAt < new Date()) {
        throw new BadRequestError('Registration session has expired');
      }

      // Check if session has been completed
      if (session.completedAt) {
        throw new BadRequestError('Registration session has already been completed');
      }

      // Check if session is a registration session
      if (!session.isRegistration) {
        throw new BadRequestError('Not a registration session');
      }

      // Get user
      const user = await this.userRepository.findById(session.userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Verify registration response based on method
      let verificationResult: VerificationResult;

      switch (session.method) {
        case 'webauthn':
          verificationResult = (await this.webAuthnService.verifyRegistration(
            session.challengeId,
            response,
            session.metadata
          )) as VerificationResult;
          break;
        case 'magic-link':
          // Magic link doesn't require registration verification
          verificationResult = {
            success: true,
            message: 'Magic link registration successful',
          };
          break;
        default:
          throw new BadRequestError(`Unsupported passwordless method: ${session.method}`);
      }

      if (!verificationResult.success) {
        // Log failed registration
        await this.auditLogService.create({
          userId: user.id,
          action: 'PASSWORDLESS_REGISTRATION_FAILED',
          entityType: 'PASSWORDLESS_SESSION',
          entityId: session.id,
          metadata: {
            method: session.method,
            identifier: session.identifier,
            reason: verificationResult.reason,
            ipAddress: options['ipAddress'],
            userAgent: options['userAgent'],
          },
        });

        // Emit registration failed event
        this.eventEmitter.emit(PasswordlessEvent.REGISTRATION_FAILED, {
          userId: user.id,
          method: session.method,
          identifier: session.identifier,
          sessionId: session.id,
          reason: verificationResult.reason,
          timestamp: new Date(),
        });

        throw new BadRequestError(verificationResult.reason || 'Registration failed');
      }

      // Update session as completed
      await this.passwordlessSessionRepository.update(sessionId, {
        completedAt: new Date(),
        metadata: {
          ...session.metadata,
          verificationResult,
        },
      });

      // Log successful registration
      await this.auditLogService.create({
        userId: user.id,
        action: 'PASSWORDLESS_REGISTRATION_COMPLETED',
        entityType: 'PASSWORDLESS_SESSION',
        entityId: session.id,
        metadata: {
          method: session.method,
          identifier: session.identifier,
          ipAddress: options['ipAddress'],
          userAgent: options['userAgent'],
        },
      });

      // Emit registration completed event
      this.eventEmitter.emit(PasswordlessEvent.REGISTRATION_COMPLETED, {
        userId: user.id,
        method: session.method,
        identifier: session.identifier,
        sessionId: session.id,
        timestamp: new Date(),
      });

      return {
        success: true,
        userId: user.id,
        method: session.method,
        message: `${session.method} registration successful`,
      };
    } catch (error) {
      logger.error('Error completing passwordless registration', { error, sessionId });
      throw error;
    }
  }

  /**
   * Get passwordless credentials for a user
   * @param userId User ID
   * @returns List of credentials
   */
  async getCredentials(userId: string): Promise<Partial<Credential>[]> {
    try {
      logger.debug('Getting passwordless credentials', { userId });

      // Check if user exists
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Get credentials
      const credentials = await this.passwordlessCredentialRepository.findByUserId(userId);

      // Sanitize credentials
      return credentials.map((credential: Credential) => ({
        id: credential.id,
        type: credential.type,
        name: credential.name,
        createdAt: credential.createdAt,
        lastUsed: credential.metadata?.lastUsed,
      }));
    } catch (error) {
      logger.error('Error getting passwordless credentials', { error, userId });
      throw error;
    }
  }

  /**
   * Delete a passwordless credential
   * @param userId User ID
   * @param credentialId Credential ID
   * @returns Deletion result
   */
  async deleteCredential(userId: string, credentialId: string): Promise<Record<string, any>> {
    try {
      logger.debug('Deleting passwordless credential', { userId, credentialId });

      // Check if user exists
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Get credential
      const credential = await this.passwordlessCredentialRepository.findById(credentialId);
      if (!credential) {
        throw new NotFoundError('Credential not found');
      }

      // Check if credential belongs to user
      if (credential.userId !== userId) {
        throw new UnauthorizedError('Credential does not belong to user');
      }

      // Delete credential
      await this.passwordlessCredentialRepository.delete(credentialId);

      // Log credential deletion
      await this.auditLogService.create({
        userId,
        action: 'PASSWORDLESS_CREDENTIAL_DELETED',
        entityType: 'PASSWORDLESS_CREDENTIAL',
        entityId: credentialId,
        metadata: {
          type: credential.type,
          name: credential.name,
        },
      });

      // Emit credential deleted event
      this.eventEmitter.emit(PasswordlessEvent.CREDENTIAL_DELETED, {
        userId,
        credentialId,
        type: credential.type,
        timestamp: new Date(),
      });

      return {
        success: true,
        message: 'Credential deleted successfully',
      };
    } catch (error) {
      logger.error('Error deleting passwordless credential', { error, userId, credentialId });
      throw error;
    }
  }

  /**
   * Validate passwordless method
   * @param method Method to validate
   */
  private validateMethod(method: string): void {
    const supportedMethods = ['webauthn', 'magic-link'];
    if (!supportedMethods.includes(method)) {
      throw new BadRequestError(`Unsupported passwordless method: ${method}`);
    }

    // Check if method is enabled
    switch (method) {
      case 'webauthn':
        if (!passwordlessConfig.webauthn.enabled) {
          throw new BadRequestError('WebAuthn authentication is not enabled');
        }
        break;
      case 'magic-link':
        if (!passwordlessConfig.magicLink.enabled) {
          throw new BadRequestError('Magic link authentication is not enabled');
        }
        break;
    }
  }

  /**
   * Find or create user based on identifier
   * @param identifier User identifier
   * @param method Authentication method
   * @returns User
   */
  private async findOrCreateUser(identifier: string, method: string): Promise<User> {
    try {
      let user;

      // Try to find user by identifier
      if (method === 'magic-link' || method === 'email-otp') {
        // For email-based methods, find by email
        user = await this.userRepository.findByEmail(identifier);
      } else if (method === 'sms-otp') {
        // For SMS-based methods, find by phone
        user = await this.userRepository.findByPhone(identifier);
      } else {
        // For other methods, try email first, then phone
        user = await this.userRepository.findByEmail(identifier);
        if (!user) {
          user = await this.userRepository.findByPhone(identifier);
        }
      }

      // If user not found, create a new one
      if (!user) {
        // Determine user data based on identifier and method
        const userData: Partial<User> = {};

        if (method === 'magic-link' || method === 'email-otp' || this.isValidEmail(identifier)) {
          userData.email = identifier;
          userData.emailVerified = true;
        } else if (method === 'sms-otp' || this.isValidPhone(identifier)) {
          userData.phoneNumber = identifier;
          userData.phoneVerified = true;
        } else {
          throw new BadRequestError('Invalid identifier format');
        }

        // Create user
        user = await this.userRepository.create({
          ...userData,
          updatedAt: new Date(),
        });

        // Log user creation
        await this.auditLogService.create({
          userId: user.id,
          action: 'USER_CREATED_VIA_PASSWORDLESS',
          entityType: 'USER',
          entityId: user.id,
          metadata: {
            method,
            identifier,
          },
        });
      }

      return user;
    } catch (error) {
      logger.error('Error finding or creating user', { error, identifier, method });
      throw error;
    }
  }

  /**
   * Generate authentication token
   * @param userId User ID
   * @param method Authentication method
   * @returns Authentication token
   */
  private generateAuthToken(userId: string, method: string): string {
    // In a real implementation, this would generate a JWT or other token
    // For now, we'll just return a placeholder
    return `passwordless_token_${userId}_${method}_${Date.now()}`;
  }

  /**
   * Sanitize user object for response
   * @param user User object
   * @returns Sanitized user
   */
  private sanitizeUser(user: User): Record<string, any> {
    return {
      id: user.id,
      email: user.email,
      phoneNumber: user.phoneNumber,
      displayName: user.displayName,
      emailVerified: user.emailVerified,
      phoneVerified: user.phoneVerified,
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt,
    };
  }

  /**
   * Validate email address
   * @param email Email to validate
   * @returns True if valid
   */
  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Validate phone number
   * @param phone Phone to validate
   * @returns True if valid
   */
  private isValidPhone(phone: string): boolean {
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;
    return phoneRegex.test(phone);
  }
}
