import { Injectable } from "@tsed/di"
import { passwordlessConfig } from "../passwordless.config"
import { logger } from "../../../infrastructure/logging/logger"
import { WebAuthnService } from "./webauthn.service"
import { PasswordlessEvent } from "../passwordless-events"
import { BadRequestError } from "../../../utils/error-handling"
import type { EventEmitter } from "../../../infrastructure/events/event-emitter"
import { Challenge, VerificationResult } from "../types"
import { WebAuthnOptions } from "../interfaces"
import { createWebAuthnOptions } from "../utils/webauthn-validator"

/**
 * Extended Challenge interface with WebAuthn specific properties
 */
interface WebAuthnChallenge extends Challenge {
  clientData: Record<string, any>;
}

/**
 * Extended VerificationResult interface with WebAuthn specific properties
 */
interface WebAuthnVerificationResult extends VerificationResult {
  userId: string;
  credentialId: string;
}

/**
 * Error with message interface for type checking
 */
interface ErrorWithMessage {
  message: string;
}

/**
 * Type guard to check if an error has a message property
 */
function isErrorWithMessage(error: unknown): error is ErrorWithMessage {
  return (
    typeof error === 'object' &&
    error !== null &&
    'message' in error &&
    typeof (error as Record<string, unknown>)['message'] === 'string'
  );
}

/**
 * Get error message from unknown error
 */
function getErrorMessage(error: unknown): string {
  if (isErrorWithMessage(error)) {
    return error.message;
  }
  return String(error);
}

/**
 * Biometric service for passwordless authentication
 * Implements biometric authentication using WebAuthn platform authenticators
 */
@Injectable()
export class BiometricService {
  constructor(
    private webAuthnService: WebAuthnService,
    private eventEmitter: EventEmitter,
  ) {}

  /**
   * Generate a registration challenge for biometric authentication
   * @param userId User ID
   * @param options Additional options
   * @returns Registration challenge
   */
  async generateRegistrationChallenge(userId: string, options: Partial<WebAuthnOptions> = {}): Promise<WebAuthnChallenge> {
    try {
      logger.debug("Generating biometric registration challenge", { userId })

      // Check if biometric authentication is enabled
      if (!passwordlessConfig.biometric.enabled) {
        throw new BadRequestError("Biometric authentication is not enabled")
      }

      // Set biometric-specific options
      const biometricOptions = createWebAuthnOptions({
        ...options,
        requireResidentKey: passwordlessConfig.biometric.requireResidentKey,
        authenticatorAttachment: "platform", // Ensure platform authenticator for biometrics
      }, 'registration')

      // Use WebAuthn service to generate challenge
      const challenge = await this.webAuthnService.generateRegistrationChallenge(userId, biometricOptions)

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.BIOMETRIC_REGISTRATION_STARTED, {
        userId,
        challengeId: challenge['id'],
        expiresAt: challenge['expiresAt'],
        timestamp: new Date(),
      })

      return challenge as WebAuthnChallenge
    } catch (error) {
      logger.error("Error generating biometric registration challenge", { error, userId })
      throw error
    }
  }

  /**
   * Verify a biometric registration response
   * @param challengeId Challenge ID
   * @param response Registration response
   * @param options Additional options
   * @returns Verification result
   */
  async verifyRegistration(
    challengeId: string,
    response: Record<string, any>,
    options: Partial<WebAuthnOptions> = {},
  ): Promise<WebAuthnVerificationResult> {
    try {
      logger.debug("Verifying biometric registration", { challengeId })

      // Set biometric-specific options
      const biometricOptions = createWebAuthnOptions({
        ...options,
        deviceType: "platform", // Mark as platform authenticator
      }, 'registration')

      // Use WebAuthn service to verify registration
      const result = await this.webAuthnService.verifyRegistration(challengeId, response, biometricOptions)

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.BIOMETRIC_REGISTRATION_COMPLETED, {
        userId: result['userId'],
        credentialId: result['credentialId'],
        timestamp: new Date(),
      })

      return result as WebAuthnVerificationResult
    } catch (error: unknown) {
      logger.error("Error verifying biometric registration", { 
        error: getErrorMessage(error), 
        challengeId 
      })

      // Emit failure event
      this.eventEmitter.emit(PasswordlessEvent.BIOMETRIC_REGISTRATION_FAILED, {
        challengeId,
        error: getErrorMessage(error),
        timestamp: new Date(),
      })

      throw error
    }
  }

  /**
   * Generate an authentication challenge for biometric authentication
   * @param userId User ID
   * @param options Additional options
   * @returns Authentication challenge
   */
  async generateAuthenticationChallenge(
    userId: string,
    options: Partial<WebAuthnOptions> = {},
  ): Promise<WebAuthnChallenge> {
    try {
      logger.debug("Generating biometric authentication challenge", { userId })

      // Check if biometric authentication is enabled
      if (!passwordlessConfig.biometric.enabled) {
        throw new BadRequestError("Biometric authentication is not enabled")
      }

      // Set biometric-specific options
      const biometricOptions = createWebAuthnOptions({
        ...options,
        userVerification: "required", // Require user verification for biometrics
        authenticatorAttachment: "platform" // Ensure platform authenticator for biometrics
      }, 'authentication')

      // Use WebAuthn service to generate challenge
      const challenge = await this.webAuthnService.generateAuthenticationChallenge(userId, biometricOptions)

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.BIOMETRIC_AUTHENTICATION_STARTED, {
        userId,
        challengeId: challenge['id'],
        expiresAt: challenge['expiresAt'],
        timestamp: new Date(),
      })

      return challenge as WebAuthnChallenge
    } catch (error) {
      logger.error("Error generating biometric authentication challenge", { error, userId })
      throw error
    }
  }

  /**
   * Verify a biometric authentication response
   * @param challengeId Challenge ID
   * @param response Authentication response
   * @param options Additional options
   * @returns Verification result
   */
  async verifyAuthentication(
    challengeId: string,
    response: Record<string, any>,
    options: Partial<WebAuthnOptions> = {},
  ): Promise<WebAuthnVerificationResult> {
    try {
      logger.debug("Verifying biometric authentication", { challengeId })

      // Validate and prepare options
      const biometricOptions = createWebAuthnOptions(options, 'authentication')
      
      // Use WebAuthn service to verify authentication
      const result = await this.webAuthnService.verifyAuthentication(challengeId, response, biometricOptions)

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.BIOMETRIC_AUTHENTICATION_COMPLETED, {
        userId: result['userId'],
        credentialId: result['credentialId'],
        timestamp: new Date(),
      })

      return result as WebAuthnVerificationResult
    } catch (error: unknown) {
      logger.error("Error verifying biometric authentication", { 
        error: getErrorMessage(error), 
        challengeId 
      })

      // Emit failure event
      this.eventEmitter.emit(PasswordlessEvent.BIOMETRIC_AUTHENTICATION_FAILED, {
        challengeId,
        error: getErrorMessage(error),
        timestamp: new Date(),
      })

      throw error
    }
  }
}
