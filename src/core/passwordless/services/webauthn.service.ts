import { Injectable } from "@tsed/di"
import { v4 as uuidv4 } from "uuid"
import { passwordlessConfig } from "../passwordless.config"
import { logger } from "../../../infrastructure/logging/logger"
import type { PasswordlessCredentialRepository } from "../../../data/repositories/passwordless/credential.repository"
import type { UserRepository } from "../../../data/repositories/user.repository"
import type { EventEmitter } from "../../../infrastructure/events/event-emitter"
import { PasswordlessEvent } from "../passwordless-events"
import { BadRequestError, NotFoundError } from "../../../utils/error-handling"
import crypto from "crypto"
import { WebAuthnOptions, UserWithDisplayName } from "../interfaces"

// In a real implementation, we would use a WebAuthn library like @simplewebauthn/server
// For this example, we'll create a simplified version with the core functionality

/**
 * WebAuthn service for passwordless authentication
 * Implements WebAuthn/FIDO2 functionality
 */
@Injectable()
export class WebAuthnService {
  constructor(
    private credentialRepository: PasswordlessCredentialRepository,
    private userRepository: UserRepository,
    private eventEmitter: EventEmitter,
  ) {}

  /**
   * Generate a registration challenge for WebAuthn
   * @param userId User ID
   * @param options Additional options
   * @returns Registration challenge
   */
  async generateRegistrationChallenge(userId: string, options: WebAuthnOptions = {}): Promise<Record<string, any>> {
    try {
      logger.debug("Generating WebAuthn registration challenge", { userId })

      // Check if WebAuthn is enabled
      if (!passwordlessConfig.webauthn.enabled) {
        throw new BadRequestError("WebAuthn is not enabled")
      }

      // Get user
      const user = await this.userRepository.findById(userId) as UserWithDisplayName
      if (!user) {
        throw new NotFoundError("User not found")
      }

      // Generate challenge
      const challenge = crypto.randomBytes(passwordlessConfig.webauthn.challengeSize).toString("base64url")
      const challengeId = uuidv4()
      const expiresAt = new Date(Date.now() + passwordlessConfig.webauthn.timeout)

      // In a real implementation, we would store the challenge in a database
      // For now, we'll return it directly

      // Get existing credentials for exclude list
      const existingCredentials = await this.credentialRepository.findWebAuthnCredentialsByUserId(userId)
      const excludeCredentials = existingCredentials.map((cred) => ({
        id: cred.credentialId,
        type: "public-key",
        transports: cred.transports || ["usb", "ble", "nfc", "internal"],
      }))

      // Prepare registration options
      const registrationOptions = {
        challenge,
        rp: {
          name: passwordlessConfig.webauthn.rpName,
          id: passwordlessConfig.webauthn.rpId,
        },
        user: {
          id: userId,
          name: user.email,
          displayName: user.displayName || user.email,
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 }, // ES256
          { type: "public-key", alg: -257 }, // RS256
        ],
        timeout: passwordlessConfig.webauthn.timeout,
        attestation: passwordlessConfig.webauthn.attestation,
        excludeCredentials,
        authenticatorSelection: {
          authenticatorAttachment: passwordlessConfig.webauthn.authenticatorAttachment,
          userVerification: passwordlessConfig.webauthn.userVerification,
          requireResidentKey: options['requireResidentKey'] || false,
        },
      }

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.WEBAUTHN_REGISTRATION_STARTED, {
        userId,
        challengeId,
        timestamp: new Date(),
      })

      return {
        id: challengeId,
        expiresAt,
        clientData: registrationOptions,
        metadata: {
          challenge,
          userId,
          origin: options['origin'],
          type: "registration",
        },
      }
    } catch (error) {
      logger.error("Error generating WebAuthn registration challenge", { error, userId })
      throw error
    }
  }

  /**
   * Verify a WebAuthn registration response
   * @param challengeId Challenge ID
   * @param response Registration response
   * @param options Additional options
   * @returns Verification result
   */
  async verifyRegistration(
    challengeId: string,
    response: Record<string, any>,
    options: WebAuthnOptions = {},
  ): Promise<Record<string, any>> {
    try {
      logger.debug("Verifying WebAuthn registration", { challengeId })

      // In a real implementation, we would retrieve the challenge from the database
      // For now, we'll assume the challenge is valid and included in the options

      // Extract challenge from options
      const challenge = options['challenge']
      if (!challenge) {
        throw new BadRequestError("Challenge not found")
      }

      // Extract user ID from options
      const userId = options['userId']
      if (!userId) {
        throw new BadRequestError("User ID not found")
      }

      // Get user
      const user = await this.userRepository.findById(userId) as UserWithDisplayName
      if (!user) {
        throw new NotFoundError("User not found")
      }

      // In a real implementation, we would verify the attestation using @simplewebauthn/server
      // For this example, we'll assume the verification is successful

      // Extract credential data from response
      const { id, type, response: attestationResponse } = response

      if (type !== "public-key") {
        throw new BadRequestError("Invalid credential type")
      }

      // Check if credential already exists
      const existingCredential = await this.credentialRepository.findWebAuthnCredentialByCredentialId(id)
      if (existingCredential) {
        throw new BadRequestError("Credential already registered")
      }

      // In a real implementation, we would extract the public key and other data from the attestation
      // For this example, we'll create a mock public key
      const publicKey = Buffer.from("mock-public-key")
      const counter = 0

      // Store credential
      const credential = await this.credentialRepository.storeWebAuthnCredential({
        userId,
        credentialId: id,
        publicKey,
        counter,
        deviceType: options['deviceType'] || "unknown",
        deviceName: options['deviceName'],
        transports: attestationResponse.transports || ["usb", "ble", "nfc", "internal"],
        metadata: {
          origin: options['origin'],
          challenge,
          registeredAt: new Date(),
          registrationIpAddress: options['ipAddress'],
          registrationUserAgent: options['userAgent'],
        },
      })

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.WEBAUTHN_REGISTRATION_COMPLETED, {
        userId,
        credentialId: credential.id,
        timestamp: new Date(),
      })

      return {
        success: true,
        credentialId: credential.id,
      }
    } catch (error) {
      logger.error("Error verifying WebAuthn registration", { error, challengeId })
      throw error
    }
  }

  /**
   * Generate an authentication challenge for WebAuthn
   * @param userId User ID
   * @param options Additional options
   * @returns Authentication challenge
   */
  async generateAuthenticationChallenge(
    userId: string,
    options: WebAuthnOptions = {},
  ): Promise<Record<string, any>> {
    try {
      logger.debug("Generating WebAuthn authentication challenge", { userId })

      // Check if WebAuthn is enabled
      if (!passwordlessConfig.webauthn.enabled) {
        throw new BadRequestError("WebAuthn is not enabled")
      }

      // Get user
      const user = await this.userRepository.findById(userId) as UserWithDisplayName
      if (!user) {
        throw new NotFoundError("User not found")
      }

      // Get user's credentials
      const credentials = await this.credentialRepository.findWebAuthnCredentialsByUserId(userId)
      if (credentials.length === 0) {
        throw new BadRequestError("No WebAuthn credentials found for user")
      }

      // Generate challenge
      const challenge = crypto.randomBytes(passwordlessConfig.webauthn.challengeSize).toString("base64url")
      const challengeId = uuidv4()
      const expiresAt = new Date(Date.now() + passwordlessConfig.webauthn.timeout)

      // Prepare authentication options
      const authenticationOptions = {
        challenge,
        timeout: passwordlessConfig.webauthn.timeout,
        rpId: passwordlessConfig.webauthn.rpId,
        allowCredentials: credentials.map((cred) => ({
          id: cred.credentialId,
          type: "public-key",
          transports: cred.transports || ["usb", "ble", "nfc", "internal"],
        })),
        userVerification: passwordlessConfig.webauthn.userVerification,
      }

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.WEBAUTHN_AUTHENTICATION_STARTED, {
        userId,
        challengeId,
        timestamp: new Date(),
      })

      return {
        id: challengeId,
        expiresAt,
        clientData: authenticationOptions,
        metadata: {
          challenge,
          userId,
          origin: options['origin'],
          type: "authentication",
        },
      }
    } catch (error) {
      logger.error("Error generating WebAuthn authentication challenge", { error, userId })
      throw error
    }
  }

  /**
   * Verify a WebAuthn authentication response
   * @param challengeId Challenge ID
   * @param response Authentication response
   * @param options Additional options
   * @returns Verification result
   */
  async verifyAuthentication(
    challengeId: string,
    response: Record<string, any>,
    options: WebAuthnOptions = {},
  ): Promise<Record<string, any>> {
    try {
      logger.debug("Verifying WebAuthn authentication", { challengeId })

      // In a real implementation, we would retrieve the challenge from the database
      // For now, we'll assume the challenge is valid and included in the options

      // Extract challenge from options
      const challenge = options['challenge']
      if (!challenge) {
        throw new BadRequestError("Challenge not found")
      }

      // Extract user ID from options
      const userId = options['userId']
      if (!userId) {
        throw new BadRequestError("User ID not found")
      }

      // Get user
      const user = await this.userRepository.findById(userId) as UserWithDisplayName
      if (!user) {
        throw new NotFoundError("User not found")
      }

      // Extract credential data from response
      const { id, type } = response

      if (type !== "public-key") {
        throw new BadRequestError("Invalid credential type")
      }

      // Find credential
      const credential = await this.credentialRepository.findWebAuthnCredentialByCredentialId(id)
      if (!credential) {
        throw new BadRequestError("Credential not found")
      }

      // Verify credential belongs to user
      if (credential.userId !== userId) {
        throw new BadRequestError("Credential does not belong to user")
      }

      // In a real implementation, we would verify the assertion using @simplewebauthn/server
      // For this example, we'll assume the verification is successful

      // Update credential counter
      const newCounter = credential.counter + 1
      await this.credentialRepository.updateWebAuthnCredential(credential.id, {
        counter: newCounter,
        lastUsedAt: new Date(),
        metadata: {
          ...credential.metadata,
          lastAuthenticationAt: new Date(),
          lastAuthenticationIpAddress: options['ipAddress'],
          lastAuthenticationUserAgent: options['userAgent'],
        },
      })

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.WEBAUTHN_AUTHENTICATION_COMPLETED, {
        userId,
        credentialId: credential.id,
        timestamp: new Date(),
      })

      return {
        success: true,
        userId,
        credentialId: credential.id,
      }
    } catch (error) {
      logger.error("Error verifying WebAuthn authentication", { error, challengeId })
      throw error
    }
  }

  /**
   * Get WebAuthn credentials for a user
   * @param userId User ID
   * @returns List of credentials
   */
  async getCredentials(userId: string): Promise<any[]> {
    try {
      logger.debug("Getting WebAuthn credentials", { userId })

      // Get user
      const user = await this.userRepository.findById(userId) as UserWithDisplayName
      if (!user) {
        throw new NotFoundError("User not found")
      }

      // Get credentials
      const credentials = await this.credentialRepository.findWebAuthnCredentialsByUserId(userId)

      // Return sanitized credentials
      return credentials.map((cred) => ({
        id: cred.id,
        credentialId: cred.credentialId,
        deviceType: cred.deviceType,
        deviceName: cred.deviceName,
        createdAt: cred.createdAt,
        lastUsedAt: cred.lastUsedAt,
      }))
    } catch (error) {
      logger.error("Error getting WebAuthn credentials", { error, userId })
      throw error
    }
  }

  /**
   * Delete a WebAuthn credential
   * @param userId User ID
   * @param credentialId Credential ID
   * @returns True if deleted, false otherwise
   */
  async deleteCredential(userId: string, credentialId: string): Promise<boolean> {
    try {
      logger.debug("Deleting WebAuthn credential", { userId, credentialId })

      // Get user
      const user = await this.userRepository.findById(userId) as UserWithDisplayName
      if (!user) {
        throw new NotFoundError("User not found")
      }

      // Get credential
      const credential = await this.credentialRepository.findWebAuthnCredentialByCredentialId(credentialId)
      if (!credential) {
        throw new NotFoundError("Credential not found")
      }

      // Verify credential belongs to user
      if (credential.userId !== userId) {
        throw new BadRequestError("Credential does not belong to user")
      }

      // Delete credential
      const result = await this.credentialRepository.deleteWebAuthnCredential(credential.id)

      // Emit event
      if (result) {
        this.eventEmitter.emit(PasswordlessEvent.CREDENTIAL_DELETED, {
          userId,
          credentialId: credential.id,
          timestamp: new Date(),
        })
      }

      return result
    } catch (error) {
      logger.error("Error deleting WebAuthn credential", { error, userId, credentialId })
      throw error
    }
  }
}
