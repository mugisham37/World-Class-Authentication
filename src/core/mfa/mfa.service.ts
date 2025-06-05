import { Injectable } from "@tsed/di"
import { v4 as uuidv4 } from "uuid"
import {
  MfaFactorType,
  MfaFactorStatus,
  MfaChallengeStatus,
  type MfaVerificationResult,
  type MfaEnrollmentResult,
} from "./mfa-factor-types"
import { MfaFactor } from "../../data/models/mfa-factor.model"
import { TotpService } from "./factors/totp.service"
import { WebAuthnService } from "./factors/webauthn.service"
import { EmailMfaService } from "./factors/email-mfa.service"
import { SmsMfaService } from "./factors/sms-mfa.service"
import { RecoveryCodeService } from "./factors/recovery-code.service"
import { PushNotificationService } from "./factors/push-notification.service"
import { MfaFactorRepository } from "../../data/repositories/mfa-factor.repository"
import { MfaChallengeRepository } from "../../data/repositories/mfa-challenge.repository"
import { UserRepository } from "../../data/repositories/user.repository"
import { mfaConfig } from "../../config/mfa-config"
import { logger } from "../../infrastructure/logging/logger"
import { BadRequestError, NotFoundError, AuthorizationError } from "../../utils/error-handling"
import { RiskAssessmentService } from "../authentication/risk-assessment.service"

@Injectable()
export class MfaService {
  constructor(
    private totpService: TotpService,
    private webAuthnService: WebAuthnService,
    private emailMfaService: EmailMfaService,
    private smsMfaService: SmsMfaService,
    private recoveryCodeService: RecoveryCodeService,
    private pushNotificationService: PushNotificationService,
    private mfaFactorRepository: MfaFactorRepository,
    private mfaChallengeRepository: MfaChallengeRepository,
    private userRepository: UserRepository,
    private auditLogService: any, // Replace with actual AuditLogService type when available
    private riskAssessmentService: RiskAssessmentService,
  ) {}

  /**
   * Get all MFA factors for a user
   * @param userId User ID
   * @returns Array of MFA factors
   */
  async getUserFactors(userId: string) {
    return this.mfaFactorRepository.findByUserId(userId)
  }

  /**
   * Get active MFA factors for a user
   * @param userId User ID
   * @returns Array of active MFA factors
   */
  async getActiveFactors(userId: string) {
    return this.mfaFactorRepository.findActiveByUserId(userId)
  }

  /**
   * Check if a user has any active MFA factors
   * @param userId User ID
   * @returns Boolean indicating if user has MFA enabled
   */
  async isMfaEnabled(userId: string): Promise<boolean> {
    const activeFactors = await this.getActiveFactors(userId)
    return activeFactors.length > 0
  }

  /**
   * Start MFA factor enrollment process
   * @param userId User ID
   * @param factorType Type of MFA factor
   * @param factorName Name for the factor
   * @param factorData Additional factor-specific data
   * @returns Enrollment result with activation data
   */
  async startFactorEnrollment(
    userId: string,
    factorType: MfaFactorType,
    factorName: string,
    factorData?: Record<string, any>,
  ): Promise<MfaEnrollmentResult> {
    // Check if user exists
    const user = await this.userRepository.findById(userId)
    if (!user) {
      throw new NotFoundError("User not found")
    }

    // Check if user has reached maximum number of active factors
    const activeFactors = await this.getActiveFactors(userId)
    if (activeFactors.length >= mfaConfig.general.maxActiveMethods) {
      throw new BadRequestError(`Maximum number of active MFA methods (${mfaConfig.general.maxActiveMethods}) reached`)
    }

    // Create enrollment based on factor type
    let enrollmentResult: MfaEnrollmentResult

    try {
      switch (factorType) {
        case MfaFactorType.TOTP:
          enrollmentResult = await this.totpService.startEnrollment(userId, factorName)
          break
        case MfaFactorType.WEBAUTHN:
          enrollmentResult = await this.webAuthnService.startEnrollment(userId, factorName, factorData)
          break
        case MfaFactorType.SMS:
          if (!factorData?.["phoneNumber"]) {
            throw new BadRequestError("Phone number is required for SMS factor")
          }
          enrollmentResult = await this.smsMfaService.startEnrollment(userId, factorName, factorData["phoneNumber"])
          break
        case MfaFactorType.EMAIL:
          enrollmentResult = await this.emailMfaService.startEnrollment(userId, factorName, user.email)
          break
        case MfaFactorType.RECOVERY_CODE:
          enrollmentResult = await this.recoveryCodeService.startEnrollment(userId, factorName)
          break
        case MfaFactorType.PUSH_NOTIFICATION:
          if (!factorData?.["deviceToken"]) {
            throw new BadRequestError("Device token is required for push notification factor")
          }
          enrollmentResult = await this.pushNotificationService.startEnrollment(
            userId,
            factorName,
            factorData["deviceToken"],
          )
          break
        default:
          throw new BadRequestError(`Unsupported MFA factor type: ${factorType}`)
      }

      // Log the enrollment attempt
      await this.auditLogService.create({
        userId,
        action: "MFA_ENROLLMENT_STARTED",
        entityType: "MFA_FACTOR",
        entityId: enrollmentResult.factorId,
        metadata: {
          factorType,
          factorName,
          success: enrollmentResult.success,
        },
      })

      return enrollmentResult
    } catch (error: any) {
      logger.error("Failed to start MFA factor enrollment", { error, userId, factorType })

      // Log the failed enrollment attempt
      await this.auditLogService.create({
        userId,
        action: "MFA_ENROLLMENT_FAILED",
        entityType: "MFA_FACTOR",
        metadata: {
          factorType,
          factorName,
          error: error.message,
        },
      })

      throw error
    }
  }

  /**
   * Complete MFA factor enrollment by verifying the factor
   * @param userId User ID
   * @param factorId Factor ID
   * @param verificationData Verification data (e.g., TOTP code, SMS code)
   * @returns Verification result
   */
  async completeFactorEnrollment(
    userId: string,
    factorId: string,
    verificationData: Record<string, any>,
  ): Promise<MfaVerificationResult> {
    // Find the factor
    const factor = await this.mfaFactorRepository.findById(factorId)
    if (!factor) {
      throw new NotFoundError("MFA factor not found")
    }

    // Verify the factor belongs to the user
    if (factor.userId !== userId) {
      throw new AuthorizationError("Unauthorized access to MFA factor")
    }

    // Verify the factor is in pending status
    if (factor.status !== MfaFactorStatus.PENDING) {
      throw new BadRequestError("MFA factor is not in pending status")
    }

    try {
      // Verify the factor based on its type
      let verificationResult: MfaVerificationResult

      switch (factor.type) {
        case MfaFactorType.TOTP:
          verificationResult = await this.totpService.verifyEnrollment(factorId, verificationData["code"])
          break
        case MfaFactorType.WEBAUTHN:
          verificationResult = await this.webAuthnService.verifyEnrollment(factorId, verificationData)
          break
        case MfaFactorType.SMS:
          verificationResult = await this.smsMfaService.verifyEnrollment(factorId, verificationData["code"])
          break
        case MfaFactorType.EMAIL:
          verificationResult = await this.emailMfaService.verifyEnrollment(factorId, verificationData["code"])
          break
        case MfaFactorType.RECOVERY_CODE:
          // Recovery codes are pre-generated and don't need verification
          verificationResult = { success: true, factorId, factorType: MfaFactorType.RECOVERY_CODE }
          break
        case MfaFactorType.PUSH_NOTIFICATION:
          verificationResult = await this.pushNotificationService.verifyEnrollment(factorId, verificationData["token"])
          break
        default:
          throw new BadRequestError(`Unsupported MFA factor type: ${factor.type}`)
      }

      if (verificationResult.success) {
        // Update factor status to active
        await this.mfaFactorRepository.update(factorId, {
          status: MfaFactorStatus.ACTIVE,
          verifiedAt: new Date(),
        })

        // Log successful verification
        await this.auditLogService.create({
          userId,
          action: "MFA_ENROLLMENT_COMPLETED",
          entityType: "MFA_FACTOR",
          entityId: factorId,
          metadata: {
            factorType: factor.type,
            factorName: factor.name,
          },
        })
      }

      return verificationResult
    } catch (error: any) {
      logger.error("Failed to complete MFA factor enrollment", { error, userId, factorId })

      // Log the failed verification
      await this.auditLogService.create({
        userId,
        action: "MFA_ENROLLMENT_VERIFICATION_FAILED",
        entityType: "MFA_FACTOR",
        entityId: factorId,
        metadata: {
          factorType: factor.type,
          factorName: factor.name,
          error: error.message,
        },
      })

      throw error
    }
  }

  /**
   * Generate MFA challenge for a specific factor
   * @param factorId Factor ID
   * @param metadata Additional metadata for the challenge
   * @returns Challenge data
   */
  async generateChallenge(factorId: string, metadata?: Record<string, any>) {
    // Find the factor
    const factor = await this.mfaFactorRepository.findById(factorId)
    if (!factor) {
      throw new NotFoundError("MFA factor not found")
    }

    // Verify the factor is active
    if (factor.status !== MfaFactorStatus.ACTIVE) {
      throw new BadRequestError("MFA factor is not active")
    }

    try {
      // Generate challenge based on factor type
      let challenge: string
      let challengeMetadata: Record<string, any> = {}

      switch (factor.type) {
        case MfaFactorType.TOTP:
          // TOTP doesn't need a server-generated challenge
          challenge = uuidv4()
          break
        case MfaFactorType.WEBAUTHN:
          const webAuthnChallenge = await this.webAuthnService.generateChallenge(factorId)
          challenge = webAuthnChallenge.challenge
          challengeMetadata = webAuthnChallenge.metadata || {}
          break
        case MfaFactorType.SMS:
          const smsChallenge = await this.smsMfaService.generateChallenge(factorId)
          challenge = smsChallenge.challenge
          break
        case MfaFactorType.EMAIL:
          const emailChallenge = await this.emailMfaService.generateChallenge(factorId)
          challenge = emailChallenge.challenge
          break
        case MfaFactorType.RECOVERY_CODE:
          // Recovery codes don't need a server-generated challenge
          challenge = uuidv4()
          break
        case MfaFactorType.PUSH_NOTIFICATION:
          const pushChallenge = await this.pushNotificationService.generateChallenge(factorId)
          challenge = pushChallenge.challenge
          challengeMetadata = pushChallenge.metadata || {}
          break
        default:
          throw new BadRequestError(`Unsupported MFA factor type: ${factor.type}`)
      }

      // Calculate expiration time
      const expiresAt = new Date(Date.now() + mfaConfig.general.challengeExpiration * 1000)

      // Create challenge record
      const challengeRecord = await this.mfaChallengeRepository.create({
        factorId,
        challenge,
        expiresAt,
        status: MfaChallengeStatus.PENDING,
        attempts: 0,
        metadata: { ...challengeMetadata, ...metadata },
      })

      // Log challenge generation
      await this.auditLogService.create({
        userId: factor.userId,
        action: "MFA_CHALLENGE_GENERATED",
        entityType: "MFA_CHALLENGE",
        entityId: challengeRecord.id,
        metadata: {
          factorId,
          factorType: factor.type,
          challengeId: challengeRecord.id,
        },
      })

      return {
        challengeId: challengeRecord.id,
        factorType: factor.type,
        expiresAt,
        metadata: challengeMetadata,
      }
    } catch (error: any) {
      logger.error("Failed to generate MFA challenge", { error, factorId })
      throw error
    }
  }

  /**
   * Verify MFA challenge response
   * @param challengeId Challenge ID
   * @param response Response to the challenge
   * @param metadata Additional metadata for verification
   * @returns Verification result
   */
  async verifyChallenge(
    challengeId: string,
    response: any,
    metadata?: Record<string, any>,
  ): Promise<MfaVerificationResult> {
    // Find the challenge
    const challenge = await this.mfaChallengeRepository.findById(challengeId)
    if (!challenge) {
      throw new NotFoundError("MFA challenge not found")
    }

    // Check if challenge is still pending
    if (challenge.status !== MfaChallengeStatus.PENDING) {
      throw new BadRequestError(`Challenge is already ${challenge.status.toLowerCase()}`)
    }

    // Check if challenge has expired
    if (challenge.expiresAt < new Date()) {
      await this.mfaChallengeRepository.update(challengeId, { status: MfaChallengeStatus.EXPIRED })
      throw new BadRequestError("Challenge has expired")
    }

    // Find the factor
    const factor = await this.mfaFactorRepository.findById(challenge.factorId)
    if (!factor) {
      throw new NotFoundError("MFA factor not found")
    }

    // Increment attempt count
    const attempts = challenge.attempts + 1
    await this.mfaChallengeRepository.update(challengeId, { attempts })

    // Check if max attempts exceeded
    if (attempts > mfaConfig.general.maxFailedAttempts) {
      await this.mfaChallengeRepository.update(challengeId, { status: MfaChallengeStatus.FAILED })

      // Log failed verification due to max attempts
      await this.auditLogService.create({
        userId: factor.userId,
        action: "MFA_VERIFICATION_MAX_ATTEMPTS",
        entityType: "MFA_CHALLENGE",
        entityId: challengeId,
        metadata: {
          factorId: factor.id,
          factorType: factor.type,
          attempts,
        },
      })

      throw new BadRequestError("Maximum verification attempts exceeded")
    }

    try {
      // Verify response based on factor type
      let verificationResult: MfaVerificationResult

      switch (factor.type) {
        case MfaFactorType.TOTP:
          verificationResult = await this.totpService.verifyChallenge(factor.id, response)
          break
        case MfaFactorType.WEBAUTHN:
          verificationResult = await this.webAuthnService.verifyChallenge(challengeId, response, metadata)
          break
        case MfaFactorType.SMS:
          verificationResult = await this.smsMfaService.verifyChallenge(challengeId, response)
          break
        case MfaFactorType.EMAIL:
          verificationResult = await this.emailMfaService.verifyChallenge(challengeId, response)
          break
        case MfaFactorType.RECOVERY_CODE:
          verificationResult = await this.recoveryCodeService.verifyChallenge(factor.id, response)
          break
        case MfaFactorType.PUSH_NOTIFICATION:
          verificationResult = await this.pushNotificationService.verifyChallenge(challengeId, response, metadata)
          break
        default:
          throw new BadRequestError(`Unsupported MFA factor type: ${factor.type}`)
      }

      // Update challenge status based on verification result
      if (verificationResult.success) {
        await this.mfaChallengeRepository.update(challengeId, {
          status: MfaChallengeStatus.COMPLETED,
          completedAt: new Date(),
          response: typeof response === "string" ? response : JSON.stringify(response),
        })

        // Update factor last used timestamp
        await this.mfaFactorRepository.update(factor.id, {
          lastUsedAt: new Date(),
        })

        // Log successful verification
        await this.auditLogService.create({
          userId: factor.userId,
          action: "MFA_VERIFICATION_SUCCEEDED",
          entityType: "MFA_CHALLENGE",
          entityId: challengeId,
          metadata: {
            factorId: factor.id,
            factorType: factor.type,
          },
        })
      } else {
        // Log failed verification
        await this.auditLogService.create({
          userId: factor.userId,
          action: "MFA_VERIFICATION_FAILED",
          entityType: "MFA_CHALLENGE",
          entityId: challengeId,
          metadata: {
            factorId: factor.id,
            factorType: factor.type,
            attempts,
          },
        })
      }

      return verificationResult
    } catch (error: any) {
      logger.error("Failed to verify MFA challenge", { error, challengeId })

      // Log verification error
      await this.auditLogService.create({
        userId: factor.userId,
        action: "MFA_VERIFICATION_ERROR",
        entityType: "MFA_CHALLENGE",
        entityId: challengeId,
        metadata: {
          factorId: factor.id,
          factorType: factor.type,
          error: error.message,
          attempts,
        },
      })

      throw error
    }
  }

  /**
   * Select appropriate MFA factors for a user based on risk assessment
   * @param userId User ID
   * @param context Authentication context (IP, device, etc.)
   * @returns Array of factor IDs to challenge
   */
  async selectFactorsForChallenge(userId: string, context: Record<string, any> = {}): Promise<string[]> {
    // Get all active factors for the user
    const activeFactors = await this.getActiveFactors(userId)
    if (activeFactors.length === 0) {
      return []
    }

    // Helper functions for safe access to factor properties
    const getFactorId = (factor: MfaFactor | undefined): string | null => {
      return factor && factor.id ? factor.id : null
    }

    // Helper function to safely get factor IDs from an array
    const getSafeFactorIds = (factors: MfaFactor[]): string[] => {
      return factors
        .filter(factor => factor && factor.id)
        .map(factor => factor.id)
    }

    // Perform risk assessment
    const riskLevel = await this.riskAssessmentService.assessLoginRisk(userId, String(context), "")

    // If adaptive MFA is enabled, select factors based on risk level
    if (mfaConfig.general.adaptiveMfaEnabled) {
      const riskLevelStr = String(riskLevel)
      switch (riskLevelStr) {
        case "high":
          // For high risk, require all available factors (except recovery codes)
          return getSafeFactorIds(
            activeFactors.filter((factor) => factor.type !== MfaFactorType.RECOVERY_CODE)
          )
        case "medium":
          // For medium risk, require strongest factor (prefer WebAuthn, then TOTP)
          const preferredFactorTypes = [
            MfaFactorType.WEBAUTHN,
            MfaFactorType.TOTP,
            MfaFactorType.SMS,
            MfaFactorType.EMAIL,
          ]
          for (const type of preferredFactorTypes) {
            const factor = activeFactors.find((f) => f.type === type)
            const factorId = getFactorId(factor)
            if (factorId) {
              return [factorId]
            }
          }
          // If no preferred factor found, use the first available
          const firstFactorId = getFactorId(activeFactors[0])
          return firstFactorId ? [firstFactorId] : []
        case "low":
          // For low risk, may skip MFA if device is remembered
          if (context["isRememberedDevice"]) {
            return []
          }
          // Otherwise, require one factor
          const lowRiskFactorId = getFactorId(activeFactors[0])
          return lowRiskFactorId ? [lowRiskFactorId] : []
        default:
          // Default to one factor
          const defaultFactorId = getFactorId(activeFactors[0])
          return defaultFactorId ? [defaultFactorId] : []
      }
    } else {
      // If adaptive MFA is disabled, always require the first active factor
      const factorId = getFactorId(activeFactors[0])
      return factorId ? [factorId] : []
    }
  }

  /**
   * Disable an MFA factor
   * @param userId User ID
   * @param factorId Factor ID
   * @returns Success status
   */
  async disableFactor(userId: string, factorId: string): Promise<boolean> {
    // Find the factor
    const factor = await this.mfaFactorRepository.findById(factorId)
    if (!factor) {
      throw new NotFoundError("MFA factor not found")
    }

    // Verify the factor belongs to the user
    if (factor.userId !== userId) {
      throw new AuthorizationError("Unauthorized access to MFA factor")
    }

    // Update factor status to disabled
    await this.mfaFactorRepository.update(factorId, {
      status: MfaFactorStatus.DISABLED,
    })

    // Log factor disabling
    await this.auditLogService.create({
      userId,
      action: "MFA_FACTOR_DISABLED",
      entityType: "MFA_FACTOR",
      entityId: factorId,
      metadata: {
        factorType: factor.type,
        factorName: factor.name,
      },
    })

    return true
  }

  /**
   * Re-enable a disabled MFA factor
   * @param userId User ID
   * @param factorId Factor ID
   * @returns Success status
   */
  async enableFactor(userId: string, factorId: string): Promise<boolean> {
    // Find the factor
    const factor = await this.mfaFactorRepository.findById(factorId)
    if (!factor) {
      throw new NotFoundError("MFA factor not found")
    }

    // Verify the factor belongs to the user
    if (factor.userId !== userId) {
      throw new AuthorizationError("Unauthorized access to MFA factor")
    }

    // Verify the factor is disabled
    if (factor.status !== MfaFactorStatus.DISABLED) {
      throw new BadRequestError("MFA factor is not disabled")
    }

    // Update factor status to active
    await this.mfaFactorRepository.update(factorId, {
      status: MfaFactorStatus.ACTIVE,
    })

    // Log factor enabling
    await this.auditLogService.create({
      userId,
      action: "MFA_FACTOR_ENABLED",
      entityType: "MFA_FACTOR",
      entityId: factorId,
      metadata: {
        factorType: factor.type,
        factorName: factor.name,
      },
    })

    return true
  }

  /**
   * Delete an MFA factor
   * @param userId User ID
   * @param factorId Factor ID
   * @returns Success status
   */
  async deleteFactor(userId: string, factorId: string): Promise<boolean> {
    // Find the factor
    const factor = await this.mfaFactorRepository.findById(factorId)
    if (!factor) {
      throw new NotFoundError("MFA factor not found")
    }

    // Verify the factor belongs to the user
    if (factor.userId !== userId) {
      throw new AuthorizationError("Unauthorized access to MFA factor")
    }

    // Delete the factor
    await this.mfaFactorRepository.delete(factorId)

    // Log factor deletion
    await this.auditLogService.create({
      userId,
      action: "MFA_FACTOR_DELETED",
      entityType: "MFA_FACTOR",
      metadata: {
        factorId,
        factorType: factor.type,
        factorName: factor.name,
      },
    })

    return true
  }

  /**
   * Regenerate recovery codes for a user
   * @param userId User ID
   * @returns New recovery codes
   */
  async regenerateRecoveryCodes(userId: string): Promise<string[]> {
    // Find existing recovery code factors
    const existingFactors = await this.mfaFactorRepository.findByUserIdAndType(userId, MfaFactorType.RECOVERY_CODE)

    // If exists, delete them
    for (const factor of existingFactors) {
      await this.mfaFactorRepository.delete(factor.id)
    }

    // Generate new recovery codes
    const result = await this.recoveryCodeService.startEnrollment(userId, "Recovery Codes")

    // Log regeneration
    await this.auditLogService.create({
      userId,
      action: "MFA_RECOVERY_CODES_REGENERATED",
      entityType: "MFA_FACTOR",
      entityId: result.factorId,
    })

    return result.recoveryCodes || []
  }
}
