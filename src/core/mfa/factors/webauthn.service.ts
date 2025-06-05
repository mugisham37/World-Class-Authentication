import { Injectable } from "@tsed/di"
// Using @ts-ignore for external libraries that might not have proper type definitions
// @ts-ignore
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server"
// @ts-ignore
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from "@simplewebauthn/typescript-types"
import type { MfaFactorRepository } from "../../../data/repositories/mfa-factor.repository"
import type { MfaChallengeRepository } from "../../../data/repositories/mfa-challenge.repository"
import type { UserRepository } from "../../../data/repositories/user.repository"
import {
  MfaFactorType,
  MfaFactorStatus,
  type MfaEnrollmentResult,
  type MfaVerificationResult,
} from "../mfa-factor-types"
import { mfaConfig } from "../../../config/mfa-config"
import { logger } from "../../../infrastructure/logging/logger"
import { BadRequestError, NotFoundError } from "../../../utils/error-handling"

@Injectable()
export class WebAuthnService {
  constructor(
    private mfaFactorRepository: MfaFactorRepository,
    private mfaChallengeRepository: MfaChallengeRepository,
    private userRepository: UserRepository,
  ) {}

  /**
   * Converts a string to a Uint8Array for WebAuthn compatibility
   * @param str String to convert
   * @returns Uint8Array representation of the string
   */
  private stringToBuffer(str: string): Uint8Array {
    try {
      if (!str) {
        throw new Error("Input string cannot be empty");
      }
      return new TextEncoder().encode(str);
    } catch (error) {
      logger.error("Failed to convert string to buffer", { error, str });
      throw new Error("Failed to process user ID");
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
    _factorData?: Record<string, any>,
  ): Promise<MfaEnrollmentResult> {
    try {
      // Get user
      const user = await this.userRepository.findById(userId)
      if (!user) {
        throw new NotFoundError("User not found")
      }

      // Generate registration options
      const rpName = mfaConfig.webAuthn.rpName
      const rpID = mfaConfig.webAuthn.rpID || ""

      // Convert userId to Uint8Array for WebAuthn compatibility
      const userIdBuffer = this.stringToBuffer(userId);

      // @ts-ignore - Ignoring all type issues with the external library
      const registrationOptions = await generateRegistrationOptions({
        // @ts-ignore
        rpName,
        // @ts-ignore
        rpID,
        userID: userIdBuffer,
        userName: user.username || user.email,
        userDisplayName: user.email,
        // @ts-ignore - Ignoring type issues with attestationType
        attestationType: mfaConfig.webAuthn.attestation,
        authenticatorSelection: {
          userVerification: mfaConfig.webAuthn.userVerification as "required" | "preferred" | "discouraged",
        },
        timeout: mfaConfig.webAuthn.timeout,
      })

      // Create factor record
      const factor = await this.mfaFactorRepository.create({
        userId,
        type: MfaFactorType.WEBAUTHN,
        name: factorName,
        status: MfaFactorStatus.PENDING,
        metadata: {
          challenge: registrationOptions.challenge,
          rpID: registrationOptions.rp.id,
          origin: mfaConfig.webAuthn.origin || "",
        },
      })

      return {
        success: true,
        factorId: factor.id,
        factorType: MfaFactorType.WEBAUTHN,
        activationData: registrationOptions,
        message: "WebAuthn registration options generated",
      }
    } catch (error: any) {
      logger.error("Failed to start WebAuthn enrollment", { error, userId })
      return {
        success: false,
        message: "Failed to start WebAuthn enrollment: " + error.message,
      }
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
    attestationResponse: RegistrationResponseJSON,
  ): Promise<MfaVerificationResult> {
    try {
      // Get factor
      const factor = await this.mfaFactorRepository.findById(factorId)
      if (!factor || factor.type !== MfaFactorType.WEBAUTHN || !factor.metadata) {
        return {
          success: false,
          message: "Invalid WebAuthn factor",
        }
      }

      // Extract expected values from factor metadata
      const expectedChallenge = factor.metadata["challenge"]
      const expectedOrigin = factor.metadata["origin"] || mfaConfig.webAuthn.origin
      const expectedRPID = factor.metadata["rpID"] || mfaConfig.webAuthn.rpID

      // Verify attestation
      // @ts-ignore - Ignoring type issues with the external library
      const verification = await verifyRegistrationResponse({
        response: attestationResponse,
        expectedChallenge,
        expectedOrigin,
        expectedRPID,
      })

      if (verification.verified) {
        // Extract credential data
        // @ts-ignore - Ignoring type issues with the external library
        const { credentialID, credentialPublicKey } = verification.registrationInfo!

        // Update factor with credential data
        await this.mfaFactorRepository.update(factorId, {
          credentialId: Buffer.from(credentialID).toString("base64url"),
          metadata: {
            ...factor.metadata,
            credentialPublicKey: Buffer.from(credentialPublicKey).toString("base64url"),
            // @ts-ignore
            counter: verification.registrationInfo!.counter,
            // @ts-ignore
            credentialDeviceType: verification.registrationInfo!.credentialDeviceType,
            // @ts-ignore
            credentialBackedUp: verification.registrationInfo!.credentialBackedUp,
          },
        })

        return {
          success: true,
          factorId,
          factorType: MfaFactorType.WEBAUTHN,
          message: "WebAuthn registration successful",
        }
      } else {
        return {
          success: false,
          factorId,
          factorType: MfaFactorType.WEBAUTHN,
          message: "WebAuthn registration verification failed",
        }
      }
    } catch (error: any) {
      logger.error("Failed to verify WebAuthn enrollment", { error, factorId })
      return {
        success: false,
        message: "Failed to verify WebAuthn enrollment: " + error.message,
      }
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
      const factor = await this.mfaFactorRepository.findById(factorId)
      if (!factor || factor.type !== MfaFactorType.WEBAUTHN || !factor.metadata) {
        throw new NotFoundError("Invalid WebAuthn factor")
      }

      // Extract credential data
      const credentialID = factor.credentialId
      if (!credentialID) {
        throw new BadRequestError("WebAuthn factor is not properly configured")
      }

      // Generate authentication options
      // @ts-ignore - Ignoring type issues with the external library
      const authenticationOptions = await generateAuthenticationOptions({
        rpID: factor.metadata["rpID"] || mfaConfig.webAuthn.rpID,
        userVerification: mfaConfig.webAuthn.userVerification as "required" | "preferred" | "discouraged",
        timeout: mfaConfig.webAuthn.timeout,
        allowCredentials: [
          {
            // @ts-ignore
            id: Buffer.from(credentialID, "base64url"),
            type: "public-key",
          },
        ],
      })

      return {
        challenge: authenticationOptions.challenge,
        metadata: {
          options: authenticationOptions,
          rpID: factor.metadata["rpID"] || mfaConfig.webAuthn.rpID,
          origin: factor.metadata["origin"] || mfaConfig.webAuthn.origin,
        },
      }
    } catch (error: any) {
      logger.error("Failed to generate WebAuthn challenge", { error, factorId })
      throw error
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
    _metadata?: Record<string, any>,
  ): Promise<MfaVerificationResult> {
    try {
      // Get challenge
      const challenge = await this.mfaChallengeRepository.findById(challengeId)
      if (!challenge || !challenge.metadata) {
        return {
          success: false,
          message: "Invalid challenge",
        }
      }

      // Get factor
      const factor = await this.mfaFactorRepository.findById(challenge.factorId)
      if (!factor || factor.type !== MfaFactorType.WEBAUTHN || !factor.metadata) {
        return {
          success: false,
          message: "Invalid WebAuthn factor",
        }
      }

      // Extract expected values
      const expectedChallenge = challenge.challenge
      const expectedOrigin = factor.metadata["origin"] || mfaConfig.webAuthn.origin
      const expectedRPID = factor.metadata["rpID"] || mfaConfig.webAuthn.rpID
      const credentialPublicKey = Buffer.from(factor.metadata["credentialPublicKey"], "base64url")
      const expectedCounter = factor.metadata["counter"] || 0

      // Verify assertion
      // @ts-ignore - Ignoring type issues with the external library
      const verification = await verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge,
        expectedOrigin,
        expectedRPID,
        // @ts-ignore
        authenticator: {
          credentialID: Buffer.from(factor.credentialId!, "base64url"),
          credentialPublicKey,
          counter: expectedCounter,
        },
      })

      if (verification.verified) {
        // Update counter
        await this.mfaFactorRepository.update(factor.id, {
          metadata: {
            ...factor.metadata,
            // @ts-ignore
            counter: verification.authenticationInfo.newCounter,
          },
        })

        return {
          success: true,
          factorId: factor.id,
          factorType: MfaFactorType.WEBAUTHN,
          message: "WebAuthn authentication successful",
        }
      } else {
        return {
          success: false,
          factorId: factor.id,
          factorType: MfaFactorType.WEBAUTHN,
          message: "WebAuthn authentication failed",
        }
      }
    } catch (error: any) {
      logger.error("Failed to verify WebAuthn challenge", { error, challengeId })
      return {
        success: false,
        message: "Failed to verify WebAuthn challenge: " + error.message,
      }
    }
  }
}
