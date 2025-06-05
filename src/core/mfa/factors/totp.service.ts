import { Injectable } from "@tsed/di"
import * as crypto from "crypto"
// @ts-ignore
import * as base32 from "hi-base32"
// @ts-ignore
import { authenticator } from "otplib"
// @ts-ignore
import * as qrcode from "qrcode"
import type { MfaFactorRepository } from "../../../data/repositories/mfa-factor.repository"
import {
  MfaFactorType,
  MfaFactorStatus,
  type MfaEnrollmentResult,
  type MfaVerificationResult,
} from "../mfa-factor-types"
import { mfaConfig } from "../../../config/mfa-config"
import { logger } from "../../../infrastructure/logging/logger"

@Injectable()
export class TotpService {
  constructor(private mfaFactorRepository: MfaFactorRepository) {
    // Configure authenticator
    authenticator.options = {
      window: mfaConfig.totp.window,
      step: mfaConfig.totp.stepSeconds,
      digits: mfaConfig.totp.digits,
      algorithm: mfaConfig.totp.algorithm.toUpperCase() as "SHA1" | "SHA256" | "SHA512",
    }
  }

  /**
   * Generate a random TOTP secret
   * @returns Base32 encoded secret
   */
  private generateSecret(): string {
    const buffer = crypto.randomBytes(mfaConfig.totp.secretLength)
    return base32.encode(buffer).replace(/=/g, "")
  }

  /**
   * Generate a QR code for TOTP setup
   * @param secret TOTP secret
   * @param accountName Account name (usually email or username)
   * @returns Data URL for QR code
   */
  private async generateQrCode(secret: string, accountName: string): Promise<string> {
    const issuer = mfaConfig.totp.issuer
    const otpauth = authenticator.keyuri(accountName, issuer, secret)

    try {
      return await qrcode.toDataURL(otpauth)
    } catch (error) {
      logger.error("Failed to generate QR code", { error })
      throw new Error("Failed to generate QR code")
    }
  }

  /**
   * Start TOTP enrollment process
   * @param userId User ID
   * @param factorName Name for the factor
   * @returns Enrollment result with secret and QR code
   */
  async startEnrollment(userId: string, factorName: string): Promise<MfaEnrollmentResult> {
    try {
      // Generate secret
      const secret = this.generateSecret()

      // Create factor record
      const factor = await this.mfaFactorRepository.create({
        userId,
        type: MfaFactorType.TOTP,
        name: factorName,
        secret,
        status: MfaFactorStatus.PENDING,
      })

      // Generate QR code
      const qrCode = await this.generateQrCode(secret, userId)

      return {
        success: true,
        factorId: factor.id,
        factorType: MfaFactorType.TOTP,
        secret,
        qrCode,
        message: "TOTP factor created. Scan the QR code with your authenticator app.",
      }
    } catch (error: any) {
      logger.error("Failed to start TOTP enrollment", { error, userId })
      return {
        success: false,
        message: "Failed to start TOTP enrollment: " + error.message,
      }
    }
  }

  /**
   * Verify TOTP enrollment by checking the provided code
   * @param factorId Factor ID
   * @param code TOTP code
   * @returns Verification result
   */
  async verifyEnrollment(factorId: string, code: string): Promise<MfaVerificationResult> {
    try {
      // Get factor
      const factor = await this.mfaFactorRepository.findById(factorId)
      if (!factor || factor.type !== MfaFactorType.TOTP || !factor.secret) {
        return {
          success: false,
          message: "Invalid TOTP factor",
        }
      }

      // Verify code
      const isValid = authenticator.verify({ token: code, secret: factor.secret })

      if (isValid) {
        return {
          success: true,
          factorId,
          factorType: MfaFactorType.TOTP,
          message: "TOTP verification successful",
        }
      } else {
        return {
          success: false,
          factorId,
          factorType: MfaFactorType.TOTP,
          message: "Invalid TOTP code",
        }
      }
    } catch (error: any) {
      logger.error("Failed to verify TOTP enrollment", { error, factorId })
      return {
        success: false,
        message: "Failed to verify TOTP enrollment: " + error.message,
      }
    }
  }

  /**
   * Verify TOTP challenge
   * @param factorId Factor ID
   * @param code TOTP code
   * @returns Verification result
   */
  async verifyChallenge(factorId: string, code: string): Promise<MfaVerificationResult> {
    try {
      // Get factor
      const factor = await this.mfaFactorRepository.findById(factorId)
      if (!factor || factor.type !== MfaFactorType.TOTP || !factor.secret) {
        return {
          success: false,
          message: "Invalid TOTP factor",
        }
      }

      // Verify code
      const isValid = authenticator.verify({ token: code, secret: factor.secret })

      if (isValid) {
        return {
          success: true,
          factorId,
          factorType: MfaFactorType.TOTP,
          message: "TOTP verification successful",
        }
      } else {
        return {
          success: false,
          factorId,
          factorType: MfaFactorType.TOTP,
          message: "Invalid TOTP code",
        }
      }
    } catch (error: any) {
      logger.error("Failed to verify TOTP challenge", { error, factorId })
      return {
        success: false,
        message: "Failed to verify TOTP challenge: " + error.message,
      }
    }
  }
}
