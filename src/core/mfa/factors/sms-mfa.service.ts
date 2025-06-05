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
import {  NotFoundError } from "../../../utils/error-handling"

@Injectable()
export class SmsMfaService {
  constructor(
    private mfaFactorRepository: MfaFactorRepository,
    private mfaChallengeRepository: MfaChallengeRepository,
    private smsService: any, // Replace with actual SMS service type
  ) {}

  /**
   * Start SMS MFA enrollment process
   * @param userId User ID
   * @param factorName Name for the factor
   * @param phoneNumber Phone number
   * @returns Enrollment result
   */
  async startEnrollment(userId: string, factorName: string, phoneNumber: string): Promise<MfaEnrollmentResult> {
    try {
      // Validate phone number format
      if (!this.isValidPhoneNumber(phoneNumber)) {
        return {
          success: false,
          message: "Invalid phone number format",
        }
      }

      // Generate verification code
      const verificationCode = this.generateVerificationCode(mfaConfig.sms.codeLength)

      // Create factor record
      const factor = await this.mfaFactorRepository.create({
        userId,
        type: MfaFactorType.SMS,
        name: factorName,
        phoneNumber,
        status: MfaFactorStatus.PENDING,
        metadata: {
          verificationCode,
          verificationExpires: new Date(Date.now() + mfaConfig.sms.expiration * 1000).toISOString(),
        },
      })

      // Send verification SMS
      await this.smsService.sendVerificationCode(phoneNumber, verificationCode)

      return {
        success: true,
        factorId: factor.id,
        factorType: MfaFactorType.SMS,
        message: `Verification code sent to ${phoneNumber}. Please check your phone.`,
      }
    } catch (error: any) {
      logger.error("Failed to start SMS MFA enrollment", { error, userId })
      return {
        success: false,
        message: "Failed to start SMS MFA enrollment: " + error.message,
      }
    }
  }

  /**
   * Verify SMS MFA enrollment
   * @param factorId Factor ID
   * @param code Verification code
   * @returns Verification result
   */
  async verifyEnrollment(factorId: string, code: string): Promise<MfaVerificationResult> {
    try {
      // Get factor
      const factor = await this.mfaFactorRepository.findById(factorId)
      if (!factor || factor.type !== MfaFactorType.SMS || !factor.metadata) {
        return {
          success: false,
          message: "Invalid SMS MFA factor",
        }
      }

      // Check if verification code has expired
      const verificationExpires = new Date(factor.metadata["verificationExpires"])
      if (verificationExpires < new Date()) {
        return {
          success: false,
          factorId,
          factorType: MfaFactorType.SMS,
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
          factorType: MfaFactorType.SMS,
          message: "Phone number verification successful",
        }
      } else {
        return {
          success: false,
          factorId,
          factorType: MfaFactorType.SMS,
          message: "Invalid verification code",
        }
      }
    } catch (error: any) {
      logger.error("Failed to verify SMS MFA enrollment", { error, factorId })
      return {
        success: false,
        message: "Failed to verify SMS MFA enrollment: " + error.message,
      }
    }
  }

  /**
   * Generate SMS MFA challenge
   * @param factorId Factor ID
   * @returns Challenge data
   */
  async generateChallenge(factorId: string) {
    try {
      // Get factor
      const factor = await this.mfaFactorRepository.findById(factorId)
      if (!factor || factor.type !== MfaFactorType.SMS) {
        throw new NotFoundError("Invalid SMS MFA factor")
      }

      // Generate verification code
      const verificationCode = this.generateVerificationCode(mfaConfig.sms.codeLength)

      // Send verification SMS
      await this.smsService.sendVerificationCode(factor.phoneNumber!, verificationCode)

      return {
        challenge: verificationCode,
      }
    } catch (error: any) {
      logger.error("Failed to generate SMS MFA challenge", { error, factorId })
      throw error
    }
  }

  /**
   * Verify SMS MFA challenge
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
      if (!factor || factor.type !== MfaFactorType.SMS) {
        return {
          success: false,
          message: "Invalid SMS MFA factor",
        }
      }

      // Verify code
      if (challenge.challenge === code) {
        return {
          success: true,
          factorId: factor.id,
          factorType: MfaFactorType.SMS,
          message: "SMS verification successful",
        }
      } else {
        return {
          success: false,
          factorId: factor.id,
          factorType: MfaFactorType.SMS,
          message: "Invalid verification code",
        }
      }
    } catch (error: any) {
      logger.error("Failed to verify SMS MFA challenge", { error, challengeId })
      return {
        success: false,
        message: "Failed to verify SMS MFA challenge: " + error.message,
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
   * Validate phone number format
   * @param phoneNumber Phone number to validate
   * @returns True if valid, false otherwise
   */
  private isValidPhoneNumber(phoneNumber: string): boolean {
    // Basic validation - can be enhanced with more sophisticated validation
    return /^\+?[1-9]\d{1,14}$/.test(phoneNumber)
  }
}
