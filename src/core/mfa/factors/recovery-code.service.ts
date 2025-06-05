import { Injectable } from "@tsed/di"
import type { MfaFactorRepository } from "../../../data/repositories/mfa-factor.repository"
import {
  MfaFactorType,
  MfaFactorStatus,
  type MfaEnrollmentResult,
  type MfaVerificationResult,
} from "../mfa-factor-types"
import { mfaConfig } from "../../../config/mfa-config"
import { logger } from "../../../infrastructure/logging/logger"
import { BadRequestError } from "../../../utils/error-handling"
import { passwordHasher } from "../../../infrastructure/security/crypto/password-hasher"

@Injectable()
export class RecoveryCodeService {
  constructor(private mfaFactorRepository: MfaFactorRepository) {}

  /**
   * Start recovery code enrollment process
   * @param userId User ID
   * @param factorName Name for the factor
   * @returns Enrollment result with recovery codes
   */
  async startEnrollment(userId: string, factorName: string): Promise<MfaEnrollmentResult> {
    try {
      // Generate recovery codes
      const recoveryCodes = this.generateRecoveryCodes(mfaConfig.recoveryCodes.count)

      // Hash the codes for storage
      const hashedCodes = await Promise.all(recoveryCodes.map(async (code) => await passwordHasher.hash(code)))

      // Create factor record
      const factor = await this.mfaFactorRepository.create({
        userId,
        type: MfaFactorType.RECOVERY_CODE,
        name: factorName,
        status: MfaFactorStatus.ACTIVE, // Recovery codes are active immediately
        metadata: {
          codes: hashedCodes,
          createdAt: new Date().toISOString(),
        },
      })

      return {
        success: true,
        factorId: factor.id,
        factorType: MfaFactorType.RECOVERY_CODE,
        recoveryCodes,
        message: "Recovery codes generated. Please save these codes in a safe place.",
      }
    } catch (error: any) {
      logger.error("Failed to start recovery code enrollment", { error, userId })
      return {
        success: false,
        message: "Failed to start recovery code enrollment: " + error.message,
      }
    }
  }

  /**
   * Verify recovery code challenge
   * @param factorId Factor ID
   * @param code Recovery code
   * @returns Verification result
   */
  async verifyChallenge(factorId: string, code: string): Promise<MfaVerificationResult> {
    try {
      // Get factor
      const factor = await this.mfaFactorRepository.findById(factorId)
      if (!factor || factor.type !== MfaFactorType.RECOVERY_CODE || !factor.metadata) {
        return {
          success: false,
          message: "Invalid recovery code factor",
        }
      }

      // Get hashed codes
      const hashedCodes = factor.metadata["codes"] || []
      if (!Array.isArray(hashedCodes) || hashedCodes.length === 0) {
        return {
          success: false,
          factorId,
          factorType: MfaFactorType.RECOVERY_CODE,
          message: "No recovery codes available",
        }
      }

      // Find matching code
      let matchIndex = -1
      for (let i = 0; i < hashedCodes.length; i++) {
        const isMatch = await passwordHasher.verify(code, hashedCodes[i])
        if (isMatch) {
          matchIndex = i
          break
        }
      }

      if (matchIndex === -1) {
        return {
          success: false,
          factorId,
          factorType: MfaFactorType.RECOVERY_CODE,
          message: "Invalid recovery code",
        }
      }

      // Remove used code
      hashedCodes.splice(matchIndex, 1)

      // Update factor with remaining codes
      await this.mfaFactorRepository.update(factorId, {
        metadata: {
          ...factor.metadata,
          codes: hashedCodes,
          lastUsedAt: new Date().toISOString(),
        },
      })

      return {
        success: true,
        factorId,
        factorType: MfaFactorType.RECOVERY_CODE,
        message: "Recovery code verification successful. This code has been used and is no longer valid.",
      }
    } catch (error: any) {
      logger.error("Failed to verify recovery code", { error, factorId })
      return {
        success: false,
        message: "Failed to verify recovery code: " + error.message,
      }
    }
  }

  /**
   * Regenerate recovery codes
   * @param factorId Factor ID
   * @returns New recovery codes
   */
  async regenerateCodes(factorId: string): Promise<string[]> {
    try {
      // Get factor
      const factor = await this.mfaFactorRepository.findById(factorId)
      if (!factor || factor.type !== MfaFactorType.RECOVERY_CODE) {
        throw new BadRequestError("Invalid recovery code factor")
      }

      // Generate new recovery codes
      const recoveryCodes = this.generateRecoveryCodes(mfaConfig.recoveryCodes.count)

      // Hash the codes for storage
      const hashedCodes = await Promise.all(recoveryCodes.map(async (code) => await passwordHasher.hash(code)))

      // Update factor with new codes
      await this.mfaFactorRepository.update(factorId, {
        metadata: {
          codes: hashedCodes,
          createdAt: new Date().toISOString(),
        },
      })

      return recoveryCodes
    } catch (error: any) {
      logger.error("Failed to regenerate recovery codes", { error, factorId })
      throw error
    }
  }

  /**
   * Generate recovery codes
   * @param count Number of codes to generate
   * @returns Array of recovery codes
   */
  private generateRecoveryCodes(count: number): string[] {
    const codes: string[] = []
    for (let i = 0; i < count; i++) {
      codes.push(this.generateRecoveryCode())
    }
    return codes
  }

  /**
   * Generate a single recovery code
   * @returns Recovery code in format XXXX-XXXX-XXXX-XXXX
   */
  private generateRecoveryCode(): string {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    let code = ""
    for (let i = 0; i < 16; i++) {
      code += chars.charAt(Math.floor(Math.random() * chars.length))
      if (i === 3 || i === 7 || i === 11) {
        code += "-"
      }
    }
    return code
  }
}
