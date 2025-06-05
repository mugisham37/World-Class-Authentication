import { Injectable } from "@tsed/di"
import * as jwt from "jsonwebtoken"
import { logger } from "../../logging/logger"

// Define StringValue type to match jsonwebtoken's internal type
type StringValue = string | Buffer

/**
 * JWT service
 * Handles JWT token operations
 */
@Injectable()
export class JwtService {
  /**
   * Sign a JWT token
   * @param payload Token payload
   * @param algorithm Signing algorithm
   * @param expiresIn Expiration time
   * @param secret Secret key (optional, uses config default if not provided)
   * @returns Signed JWT token
   */
  async sign(
    payload: Record<string, any>,
    algorithm: string = "HS256",
    expiresIn?: string | number,
    secret?: string
  ): Promise<string> {
    try {
      // In a real implementation, this would use a proper secret from config
      const jwtSecret = secret || process.env["JWT_SECRET"] || "default-secret-for-development-only"
      
      const options: jwt.SignOptions = {
        algorithm: algorithm as jwt.Algorithm,
      }
      
      // Only set expiresIn if it's provided
      if (expiresIn !== undefined) {
        // Force the type to be compatible with jsonwebtoken
        options.expiresIn = expiresIn as any
      }
      
      return jwt.sign(payload, jwtSecret, options)
    } catch (error) {
      logger.error("Error signing JWT", { error })
      throw error
    }
  }

  /**
   * Verify a JWT token
   * @param token JWT token to verify
   * @param secret Secret key (optional, uses config default if not provided)
   * @returns Decoded token payload
   */
  async verify(token: string, secret?: string): Promise<Record<string, any>> {
    try {
      // In a real implementation, this would use a proper secret from config
      const jwtSecret = secret || process.env["JWT_SECRET"] || "default-secret-for-development-only"
      
      return jwt.verify(token, jwtSecret) as Record<string, any>
    } catch (error) {
      logger.error("Error verifying JWT", { error })
      throw error
    }
  }

  /**
   * Decode a JWT token without verification
   * @param token JWT token to decode
   * @returns Decoded token payload
   */
  decode(token: string): Record<string, any> | null {
    try {
      const decoded = jwt.decode(token)
      return decoded as Record<string, any>
    } catch (error) {
      logger.error("Error decoding JWT", { error })
      return null
    }
  }
}
