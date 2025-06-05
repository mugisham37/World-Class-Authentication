import { Injectable } from "@tsed/di"
import { v4 as uuidv4 } from "uuid"
import { Token, TokenType, CreateTokenInput, UpdateTokenInput } from "../models/token.model"
import { logger } from "../../../infrastructure/logging/logger"
import { EventEmitter } from "../../../infrastructure/events/event-emitter"
import { OAuthEvent } from "../oauth-events"
import { NotFoundError } from "../../../utils/error-handling"

/**
 * Service for managing OAuth tokens
 */
@Injectable()
export class TokenService {
  constructor(
    private eventEmitter: EventEmitter,
    // In a real implementation, this would be injected from a repository
    // private tokenRepository: TokenRepository
  ) {}

  // In-memory token storage for demonstration
  private tokens: Map<string, Token> = new Map()

  /**
   * Find token by ID
   * @param id Token ID
   * @returns Token or null if not found
   */
  async findById(id: string): Promise<Token | null> {
    try {
      // In a real implementation, this would query the database
      const token = this.tokens.get(id)
      return token || null
    } catch (error) {
      logger.error("Error finding token by ID", { error, id })
      return null
    }
  }

  /**
   * Find token by value and type
   * @param value Token value
   * @param type Token type
   * @returns Token or null if not found
   */
  async findByValue(value: string, type: TokenType): Promise<Token | null> {
    try {
      // In a real implementation, this would query the database
      for (const token of this.tokens.values()) {
        if (token.value === value && token.type === type) {
          return token
        }
      }
      return null
    } catch (error) {
      logger.error("Error finding token by value", { error, type })
      return null
    }
  }

  /**
   * Find tokens by client ID
   * @param clientId Client ID
   * @returns Array of tokens
   */
  async findByClientId(clientId: string): Promise<Token[]> {
    try {
      // In a real implementation, this would query the database
      const tokens: Token[] = []
      for (const token of this.tokens.values()) {
        if (token.clientId === clientId) {
          tokens.push(token)
        }
      }
      return tokens
    } catch (error) {
      logger.error("Error finding tokens by client ID", { error, clientId })
      return []
    }
  }

  /**
   * Find tokens by user ID
   * @param userId User ID
   * @returns Array of tokens
   */
  async findByUserId(userId: string): Promise<Token[]> {
    try {
      // In a real implementation, this would query the database
      const tokens: Token[] = []
      for (const token of this.tokens.values()) {
        if (token.userId === userId) {
          tokens.push(token)
        }
      }
      return tokens
    } catch (error) {
      logger.error("Error finding tokens by user ID", { error, userId })
      return []
    }
  }

  /**
   * Create a new token
   * @param data Token data
   * @returns Created token
   */
  async create(data: CreateTokenInput): Promise<Token> {
    try {
      // Generate token ID
      const id = uuidv4()

      // Create token
      const token: Token = {
        ...data,
        id,
        issuedAt: new Date(),
      }

      // In a real implementation, this would save to the database
      this.tokens.set(id, token)

      // Emit token issued event for access and refresh tokens
      if (token.type === TokenType.ACCESS_TOKEN || token.type === TokenType.REFRESH_TOKEN) {
        this.eventEmitter.emit(OAuthEvent.TOKEN_ISSUED, {
          clientId: token.clientId,
          userId: token.userId,
          tokenId: token.id,
          timestamp: new Date(),
        })
      }

      return token
    } catch (error) {
      logger.error("Error creating token", { error })
      throw error
    }
  }

  /**
   * Update a token
   * @param id Token ID
   * @param data Token data to update
   * @returns Updated token
   */
  async update(id: string, data: UpdateTokenInput): Promise<Token> {
    try {
      // Find token
      const token = await this.findById(id)
      if (!token) {
        throw new NotFoundError("Token not found")
      }

      // Update token
      const updatedToken: Token = {
        ...token,
        ...data,
      }

      // In a real implementation, this would update the database
      this.tokens.set(id, updatedToken)

      return updatedToken
    } catch (error) {
      logger.error("Error updating token", { error, id })
      throw error
    }
  }

  /**
   * Revoke a token
   * @param id Token ID
   * @returns True if revoked
   */
  async revoke(id: string): Promise<boolean> {
    try {
      // Find token
      const token = await this.findById(id)
      if (!token) {
        throw new NotFoundError("Token not found")
      }

      // Check if already revoked
      if (token.revokedAt) {
        return true
      }

      // Revoke token
      const revokedToken: Token = {
        ...token,
        revokedAt: new Date(),
      }

      // In a real implementation, this would update the database
      this.tokens.set(id, revokedToken)

      // Emit token revoked event
      this.eventEmitter.emit(OAuthEvent.TOKEN_REVOKED, {
        clientId: token.clientId,
        userId: token.userId,
        tokenId: token.id,
        timestamp: new Date(),
      })

      return true
    } catch (error) {
      logger.error("Error revoking token", { error, id })
      throw error
    }
  }

  /**
   * Revoke all tokens for a client
   * @param clientId Client ID
   * @returns Number of tokens revoked
   */
  async revokeAllForClient(clientId: string): Promise<number> {
    try {
      // Find tokens for client
      const tokens = await this.findByClientId(clientId)
      let count = 0

      // Revoke each token
      for (const token of tokens) {
        if (!token.revokedAt) {
          await this.revoke(token.id)
          count++
        }
      }

      return count
    } catch (error) {
      logger.error("Error revoking all tokens for client", { error, clientId })
      throw error
    }
  }

  /**
   * Revoke all tokens for a user
   * @param userId User ID
   * @returns Number of tokens revoked
   */
  async revokeAllForUser(userId: string): Promise<number> {
    try {
      // Find tokens for user
      const tokens = await this.findByUserId(userId)
      let count = 0

      // Revoke each token
      for (const token of tokens) {
        if (!token.revokedAt) {
          await this.revoke(token.id)
          count++
        }
      }

      return count
    } catch (error) {
      logger.error("Error revoking all tokens for user", { error, userId })
      throw error
    }
  }

  /**
   * Clean up expired tokens
   * @returns Number of tokens cleaned up
   */
  async cleanupExpiredTokens(): Promise<number> {
    try {
      const now = new Date()
      let count = 0

      // In a real implementation, this would be a database query
      for (const [id, token] of this.tokens.entries()) {
        if (token.expiresAt < now) {
          this.tokens.delete(id)
          count++
        }
      }

      return count
    } catch (error) {
      logger.error("Error cleaning up expired tokens", { error })
      throw error
    }
  }

  /**
   * Validate token
   * @param value Token value
   * @param type Token type
   * @returns Validation result
   */
  async validateToken(
    value: string,
    type: TokenType
  ): Promise<{
    valid: boolean
    token?: Token
    error?: string
  }> {
    try {
      // Find token
      const token = await this.findByValue(value, type)
      if (!token) {
        return { valid: false, error: "Token not found" }
      }

      // Check if token is expired
      if (token.expiresAt < new Date()) {
        return { valid: false, error: "Token expired" }
      }

      // Check if token is revoked
      if (token.revokedAt) {
        return { valid: false, error: "Token revoked" }
      }

      // Emit token validated event
      this.eventEmitter.emit(OAuthEvent.TOKEN_VALIDATED, {
        clientId: token.clientId,
        userId: token.userId,
        tokenId: token.id,
        timestamp: new Date(),
      })

      return { valid: true, token }
    } catch (error) {
      logger.error("Error validating token", { error })
      return { valid: false, error: "Error validating token" }
    }
  }
}
