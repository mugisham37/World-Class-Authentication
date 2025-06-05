import { Injectable } from "@tsed/di"
import type { MfaFactorRepository } from "../../../data/repositories/mfa-factor.repository"
import type { MfaChallengeRepository } from "../../../data/repositories/mfa-challenge.repository"
import {
  MfaFactorType,
  MfaFactorStatus,
  type MfaEnrollmentResult,
  type MfaVerificationResult,
} from "../mfa-factor-types"
import { mfaConfig } from "../../../config/mfa-config"
import { logger } from "../../../infrastructure/logging/logger"
import { NotFoundError } from "../../../utils/error-handling"

@Injectable()
export class EmailMfaService {
  constructor(
    private mfaFactorRepository: MfaFactorRepository,
    private mfaChallengeRepository: MfaChallengeRepository,
    private emailService: any, // Replace with actual Email service type
  ) {}

  /**
   * Start email MFA enrollment process
   * @param userId User ID
   * @param factorName Name for the factor
   * @param email Email address
   * @returns Enrollment result
   */
  async startEnrollment(userId: string, factorName: string, email: string): Promise<MfaEnrollmentResult> {
    try {
      // Validate email format
      if (!this.isValidEmail(email)) {
        return {
          success: false,
          message: "Invalid email format",
        }
      }

      // Generate verification code
      const verificationCode = this.generateVerificationCode(mfaConfig.email.codeLength)

      // Create factor record
      const factor = await this.mfaFactorRepository.create({
        userId,
        type: MfaFactorType.EMAIL,
        name: factorName,
        email,
        status: MfaFactorStatus.PENDING,
        metadata: {
          verificationCode,
          verificationExpires: new Date(Date.now() + mfaConfig.email.expiration * 1000).toISOString(),
        },
      })

      // Send verification email
      await this.emailService.sendMfaVerificationCode(email, verificationCode)

      return {
        success: true,
        factorId: factor.id,
        factorType: MfaFactorType.EMAIL,
        message: `Verification code sent to ${email}. Please check your email.`,
      }
    } catch (error: any) {
      logger.error("Failed to start email MFA enrollment", { error, userId })
      return {
        success: false,
        message: "Failed to start email MFA enrollment: " + error.message,
      }
    }
  }

  /**
   * Verify email MFA enrollment
   * @param factorId Factor ID
   * @param code Verification code
   * @returns Verification result
   */
  async verifyEnrollment(factorId: string, code: string): Promise<MfaVerificationResult> {
    try {
      // Get factor
      const factor = await this.mfaFactorRepository.findById(factorId)
      if (!factor || factor.type !== MfaFactorType.EMAIL || !factor.metadata) {
        return {
          success: false,
          message: "Invalid email MFA factor",
        }
      }

      // Check if verification code has expired
      const verificationExpires = new Date(factor.metadata["verificationExpires"])
      if (verificationExpires < new Date()) {
        return {
          success: false,
          factorId,
          factorType: MfaFactorType.EMAIL,
          message: "Verification code has expired",
        }
      }

      // Verify code
      if (factor.metadata["verificationCode"] === code) {
        // Remove verification code from metadata
        const { verificationCode, verificationExpires, ...restMetadata } = factor.metadata

        // Update factor metadata
        await this.mfaFactorRepository.update(factorId, {
          metadata: restMetadata,
        })

        return {
          success: true,
          factorId,
          factorType: MfaFactorType.EMAIL,
          message: "Email verification successful",
        }
      } else {
        return {
          success: false,
          factorId,
          factorType: MfaFactorType.EMAIL,
          message: "Invalid verification code",
        }
      }
    } catch (error: any) {
      logger.error("Failed to verify email MFA enrollment", { error, factorId })
      return {
        success: false,
        message: "Failed to verify email MFA enrollment: " + error.message,
      }
    }
  }

  /**
   * Generate email MFA challenge
   * @param factorId Factor ID
   * @returns Challenge data
   */
  async generateChallenge(factorId: string) {
    try {
      // Get factor
      const factor = await this.mfaFactorRepository.findById(factorId)
      if (!factor || factor.type !== MfaFactorType.EMAIL) {
        throw new NotFoundError("Invalid email MFA factor")
      }

      // Generate verification code
      const verificationCode = this.generateVerificationCode(mfaConfig.email.codeLength)

      // Send verification email
      await this.emailService.sendMfaVerificationCode(factor.email!, verificationCode)

      return {
        challenge: verificationCode,
      }
    } catch (error: any) {
      logger.error("Failed to generate email MFA challenge", { error, factorId })
      throw error
    }
  }

  /**
   * Verify email MFA challenge
   * @param challengeId Challenge ID
   * @param code Verification code
   * @returns Verification result
   */
  async verifyChallenge(challengeId: string, code: string): Promise<MfaVerificationResult> {
    try {
      // Get challenge
      const challenge = await this.mfaChallengeRepository.findById(challengeId)
      if (!challenge) {
        return {
          success: false,
          message: "Invalid challenge",
        }
      }

      // Get factor
      const factor = await this.mfaFactorRepository.findById(challenge.factorId)
      if (!factor || factor.type !== MfaFactorType.EMAIL) {
        return {
          success: false,
          message: "Invalid email MFA factor",
        }
      }

      // Verify code
      if (challenge.challenge === code) {
        return {
          success: true,
          factorId: factor.id,
          factorType: MfaFactorType.EMAIL,
          message: "Email verification successful",
        }
      } else {
        return {
          success: false,
          factorId: factor.id,
          factorType: MfaFactorType.EMAIL,
          message: "Invalid verification code",
        }
      }
    } catch (error: any) {
      logger.error("Failed to verify email MFA challenge", { error, challengeId })
      return {
        success: false,
        message: "Failed to verify email MFA challenge: " + error.message,
      }
    }
  }

  /**
   * Generate a random verification code
   * @param length Length of the code
   * @returns Verification code
   */
  private generateVerificationCode(length: number): string {
    return Math.floor(Math.pow(10, length - 1) + Math.random() * 9 * Math.pow(10, length - 1)).toString()
  }

  /**
   * Validate email format
   * @param email Email to validate
   * @returns True if valid, false otherwise
   */
  private isValidEmail(email: string): boolean {
    // Basic email validation
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  }
}
