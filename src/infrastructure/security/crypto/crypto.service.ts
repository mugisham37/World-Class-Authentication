import { Injectable } from "@tsed/di"
import * as crypto from "crypto"
import * as jwt from "jsonwebtoken"

/**
 * Crypto Service
 * Provides cryptographic utilities for the application
 */
@Injectable()
export class CryptoService {
  /**
   * Generate a random string
   * @param length Length of the string
   * @returns Random string
   */
  generateRandomString(length: number): string {
    return crypto.randomBytes(Math.ceil(length / 2)).toString("hex").slice(0, length)
  }

  /**
   * Generate a UUID
   * @returns UUID
   */
  generateUuid(): string {
    return crypto.randomUUID()
  }

  /**
   * Hash a string using SHA-256
   * @param value String to hash
   * @returns Hashed string
   */
  hash(value: string): string {
    return crypto.createHash("sha256").update(value).digest("hex")
  }

  /**
   * Generate a PKCE code challenge
   * @param codeVerifier Code verifier
   * @returns Code challenge
   */
  generateCodeChallenge(codeVerifier: string): string {
    const hash = crypto.createHash("sha256").update(codeVerifier).digest("base64")
    return hash.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
  }

  /**
   * Generate a token hash (for at_hash, c_hash, etc.)
   * @param token Token to hash
   * @param algorithm Algorithm to use
   * @returns Token hash
   */
  generateTokenHash(token: string, algorithm: string): string {
    const hash = crypto.createHash(algorithm === "RS256" ? "sha256" : "sha1").update(token).digest()
    const halfHash = Buffer.from(hash.slice(0, hash.length / 2))
    return halfHash.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
  }

  /**
   * Sign a JWT
   * @param payload Payload to sign
   * @param secret Secret or private key
   * @param options Options
   * @returns Signed JWT
   */
  async sign(payload: Record<string, any>, secret: string, options?: jwt.SignOptions): Promise<string> {
    return jwt.sign(payload, secret, options)
  }

  /**
   * Verify a JWT
   * @param token Token to verify
   * @param secret Secret or public key
   * @param options Options
   * @returns Decoded payload
   */
  async verifyJwt(token: string, secret: string, options?: jwt.VerifyOptions): Promise<Record<string, any>> {
    return jwt.verify(token, secret, options) as Record<string, any>
  }

  /**
   * Decode a JWT without verification
   * @param token Token to decode
   * @returns Decoded payload
   */
  decodeJwt(token: string): Record<string, any> | null {
    return jwt.decode(token) as Record<string, any> | null
  }

  /**
   * Encrypt a value
   * @param value Value to encrypt
   * @param key Encryption key
   * @returns Encrypted value
   */
  encrypt(value: string, key: string): string {
    const iv = crypto.randomBytes(16)
    const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(key), iv)
    let encrypted = cipher.update(value, "utf8", "hex")
    encrypted += cipher.final("hex")
    return `${iv.toString("hex")}:${encrypted}`
  }

  /**
   * Decrypt a value
   * @param value Value to decrypt
   * @param key Encryption key
   * @returns Decrypted value
   */
  decrypt(value: string, key: string): string {
    const parts = value.split(":")
    if (parts.length !== 2) {
      throw new Error("Invalid encrypted value format")
    }
    
    const ivHex = parts[0]
    const encryptedHex = parts[1]
    
    if (!ivHex || !encryptedHex) {
      throw new Error("Invalid encrypted value format")
    }
    
    const iv = Buffer.from(ivHex, "hex")
    const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(key), iv)
    let decrypted = decipher.update(encryptedHex, "hex", "utf8")
    decrypted += decipher.final("utf8")
    return decrypted
  }
}
