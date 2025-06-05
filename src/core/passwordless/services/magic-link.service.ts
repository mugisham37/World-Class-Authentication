import { Injectable } from "@tsed/di"
import crypto from "crypto"
import { v4 as uuidv4 } from "uuid"
import type { PasswordlessCredentialRepository } from "../../../data/repositories/passwordless/credential.repository"
import type { UserRepository } from "../../../data/repositories/user.repository"
import type { EventEmitter } from "../../../infrastructure/events/event-emitter"
import { logger } from "../../../infrastructure/logging/logger"
import { BadRequestError, NotFoundError } from "../../../utils/error-handling"
import type { EmailService } from "../../notifications/email.service"
import { PasswordlessEvent } from "../passwordless-events"
import { passwordlessConfig } from "../passwordless.config"
import { MagicLinkOptions } from "../interfaces/magic-link-options"
import { MagicLink, MagicLinkData } from "../types"

/**
 * Magic link service for passwordless authentication
 * Implements magic link functionality for email-based authentication
 */
@Injectable()
export class MagicLinkService {
  constructor(
    private credentialRepository: PasswordlessCredentialRepository,
    private userRepository: UserRepository,
    private emailService: EmailService,
    private eventEmitter: EventEmitter,
  ) {}

  /**
   * Send a magic link to the user's email
   * @param userId User ID
   * @param email User's email
   * @param options Additional options
   * @returns Magic link challenge
   */
  async sendMagicLink(userId: string, email: string, options: MagicLinkOptions = {}): Promise<Record<string, any>> {
    try {
      logger.debug("Sending magic link", { userId, email })

      // Check if magic link authentication is enabled
      if (!passwordlessConfig.magicLink.enabled) {
        throw new BadRequestError("Magic link authentication is not enabled")
      }

      // Get user
      const user = await this.userRepository.findById(userId)
      if (!user) {
        throw new NotFoundError("User not found")
      }

      // Verify email matches user's email
      if (user.email !== email) {
        throw new BadRequestError("Email does not match user's email")
      }

      // Check if email is verified (optional based on config)
      if (!user.emailVerified && passwordlessConfig.magicLink.requireVerifiedEmail) {
        throw new BadRequestError("Email is not verified")
      }

      // Check allowed domains if configured
      if (passwordlessConfig.magicLink.allowedDomains && passwordlessConfig.magicLink.allowedDomains.length > 0) {
        const emailDomain = email.split("@")[1] || ""
        if (!passwordlessConfig.magicLink.allowedDomains.includes(emailDomain)) {
          throw new BadRequestError(`Email domain not allowed: ${emailDomain}`)
        }
      }

      // Check if user has too many active magic links
      const activeLinks = await this.credentialRepository.findActiveMagicLinksByUserId(userId)
      if (activeLinks.length >= passwordlessConfig.magicLink.maxTokensPerUser) {
        throw new BadRequestError(`Too many active magic links (max: ${passwordlessConfig.magicLink.maxTokensPerUser})`)
      }

      // Check for recent magic links that can be reused
      if (passwordlessConfig.magicLink.reuseWindow > 0 && activeLinks.length > 0) {
        const recentLinks = activeLinks.filter(
          (link: MagicLink) => Date.now() - link.createdAt.getTime() < passwordlessConfig.magicLink.reuseWindow * 1000
        )
        
        if (recentLinks.length > 0) {
          // Reuse the most recent link (we know it exists because we checked length > 0)
          const recentLink = recentLinks[0]!
          
          // Send email with magic link
          await this.sendMagicLinkEmail(email, recentLink.token, {
            userId,
            expiresIn: Math.floor((recentLink.expiresAt.getTime() - Date.now()) / 1000),
            ipAddress: options.ipAddress,
            userAgent: options.userAgent,
          })
          
          // Emit event
          this.eventEmitter.emit(PasswordlessEvent.MAGIC_LINK_SENT, {
            userId,
            email,
            magicLinkId: recentLink.id,
            expiresAt: recentLink.expiresAt,
            reused: true,
            timestamp: new Date(),
          })
          
          return {
            id: recentLink.id,
            expiresAt: recentLink.expiresAt,
            email,
            reused: true,
            metadata: {
              origin: options.origin,
            },
          }
        }
      }

      // Generate token
      const token = this.generateToken()
      const expiresAt = new Date(Date.now() + passwordlessConfig.magicLink.tokenExpiration * 1000)

      // Store magic link
      const magicLinkId = uuidv4()
      const magicLinkData: MagicLinkData = {
        id: magicLinkId,
        userId,
        email,
        token,
        expiresAt,
        used: false,
        metadata: {
          ipAddress: options.ipAddress,
          userAgent: options.userAgent,
          origin: options.origin,
          requestedAt: new Date(),
        },
      }
      
      await this.credentialRepository.storeMagicLink(magicLinkData)

      // Send email with magic link
      await this.sendMagicLinkEmail(email, token, {
        userId,
        expiresIn: passwordlessConfig.magicLink.tokenExpiration,
        ipAddress: options.ipAddress,
        userAgent: options.userAgent,
      })

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.MAGIC_LINK_SENT, {
        userId,
        email,
        magicLinkId,
        expiresAt,
        reused: false,
        timestamp: new Date(),
      })

      return {
        id: magicLinkId,
        expiresAt,
        email,
        reused: false,
        metadata: {
          origin: options.origin,
        },
      }
    } catch (error) {
      logger.error("Error sending magic link", { error, userId, email })
      throw error
    }
  }

  /**
   * Verify a magic link token
   * @param magicLinkId Magic link ID
   * @param token Magic link token
   * @param options Additional options
   * @returns Verification result
   */
  async verifyMagicLink(
    magicLinkId: string,
    token: string,
    options: MagicLinkOptions = {},
  ): Promise<Record<string, any>> {
    try {
      logger.debug("Verifying magic link", { magicLinkId })

      // Find magic link
      const magicLink = await this.credentialRepository.findMagicLinkById(magicLinkId)
      if (!magicLink) {
        throw new NotFoundError("Magic link not found")
      }

      // Check if magic link has expired
      if (magicLink.expiresAt < new Date()) {
        // Emit event
        this.eventEmitter.emit(PasswordlessEvent.MAGIC_LINK_EXPIRED, {
          userId: magicLink.userId,
          magicLinkId,
          timestamp: new Date(),
        })

        throw new BadRequestError("Magic link has expired")
      }

      // Check if magic link has been used
      if (magicLink.used) {
        throw new BadRequestError("Magic link has already been used")
      }

      // Verify token
      if (magicLink.token !== token) {
        // Emit event
        this.eventEmitter.emit(PasswordlessEvent.MAGIC_LINK_FAILED, {
          userId: magicLink.userId,
          magicLinkId,
          timestamp: new Date(),
        })

        throw new BadRequestError("Invalid magic link token")
      }

      // Get user
      const user = await this.userRepository.findById(magicLink.userId)
      if (!user) {
        throw new NotFoundError("User not found")
      }

      // Mark magic link as used
      await this.credentialRepository.updateMagicLink(magicLinkId, {
        used: true,
        metadata: {
          ...magicLink.metadata,
          verificationIpAddress: options.ipAddress,
          verificationUserAgent: options.userAgent,
          verifiedAt: new Date(),
        },
      })

      // Emit event
      this.eventEmitter.emit(PasswordlessEvent.MAGIC_LINK_VERIFIED, {
        userId: user.id,
        email: magicLink.email,
        magicLinkId,
        timestamp: new Date(),
      })

      return {
        success: true,
        userId: user.id,
        email: magicLink.email,
      }
    } catch (error) {
      logger.error("Error verifying magic link", { error, magicLinkId })
      throw error
    }
  }

  /**
   * Generate a secure token for magic links
   * @returns Secure token
   */
  private generateToken(): string {
    const tokenLength = passwordlessConfig.magicLink.tokenLength
    const buffer = crypto.randomBytes(Math.ceil(tokenLength / 2))
    return buffer.toString("hex").slice(0, tokenLength)
  }

  /**
   * Send an email with a magic link
   * @param email Recipient email
   * @param token Magic link token
   * @param options Additional options
   */
  private async sendMagicLinkEmail(
    email: string,
    token: string,
    options: MagicLinkOptions = {},
  ): Promise<void> {
    try {
      // Construct magic link URL
      const baseUrl = options.origin || process.env.APP_URL || "http://localhost:3000"
      const magicLinkUrl = `${baseUrl}/auth/verify-magic-link?token=${token}`

      // Send email
      await this.emailService.sendMagicLink(email, magicLinkUrl, {
        userId: options.userId || "",
        expiresIn: options.expiresIn || 0,
        ipAddress: options.ipAddress,
        userAgent: options.userAgent,
      })
    } catch (error) {
      logger.error("Error sending magic link email", { error, email })
      throw error
    }
  }
}
