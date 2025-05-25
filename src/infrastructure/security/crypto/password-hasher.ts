import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { logger } from '../../logging/logger';
import { securityConfig } from '../../../config/security-config';

/**
 * Interface for password hash options
 */
interface PasswordHashOptions {
  algorithm?: 'bcrypt' | 'argon2' | 'pbkdf2';
  cost?: number;
}

/**
 * Interface for password generation options
 */
interface PasswordGenerationOptions {
  includeLowercase?: boolean;
  includeUppercase?: boolean;
  includeNumbers?: boolean;
  includeSymbols?: boolean;
}

/**
 * Password Hasher Service
 * Implements secure password hashing with algorithm abstraction and migration support
 */
class PasswordHasher {
  // Default cost factor for bcrypt
  private readonly defaultCost: number;

  // Pepper for additional security (if configured)
  private readonly pepper: string | undefined;

  // Supported hashing algorithms
  private readonly algorithms = {
    BCRYPT: 'bcrypt',
    ARGON2: 'argon2',
    PBKDF2: 'pbkdf2',
  } as const;

  constructor() {
    this.defaultCost = securityConfig.password.saltRounds;
    this.pepper = securityConfig.password.pepper;
  }

  /**
   * Hash a password
   * @param password Plain text password
   * @param options Hashing options
   * @returns Hashed password with metadata
   */
  async hash(password: string, options: PasswordHashOptions = {}): Promise<string> {
    const { algorithm = this.algorithms.BCRYPT, cost = this.defaultCost } = options;

    try {
      // Apply pepper if configured
      const pepperedPassword = this.applyPepper(password);

      // Hash the password using the specified algorithm
      let hashedPassword: string;
      let metadata: Record<string, any> = {};

      switch (algorithm) {
        case this.algorithms.BCRYPT:
          hashedPassword = await this.hashWithBcrypt(pepperedPassword, cost);
          metadata = { alg: algorithm, cost };
          break;

        case this.algorithms.ARGON2:
          hashedPassword = await this.hashWithArgon2(pepperedPassword);
          metadata = { alg: algorithm };
          break;

        case this.algorithms.PBKDF2:
          const { hash, salt, iterations } = await this.hashWithPbkdf2(pepperedPassword);
          hashedPassword = hash;
          metadata = { alg: algorithm, salt, iterations };
          break;

        default:
          throw new Error(`Unsupported hashing algorithm: ${algorithm}`);
      }

      // Create result with metadata
      const result = {
        v: 1, // Version
        ...metadata,
        hash: hashedPassword,
      };

      // Return JSON string
      return JSON.stringify(result);
    } catch (error) {
      logger.error('Failed to hash password', { error, algorithm });
      throw new Error('Failed to hash password');
    }
  }

  /**
   * Verify a password against a hash
   * @param password Plain text password
   * @param hashedPassword Hashed password with metadata
   * @returns Whether the password matches
   */
  async verify(password: string, hashedPassword: string): Promise<boolean> {
    try {
      // Parse hashed password
      const parsed = JSON.parse(hashedPassword);

      // Validate version
      if (parsed.v !== 1) {
        throw new Error(`Unsupported hash version: ${parsed.v}`);
      }

      // Apply pepper if configured
      const pepperedPassword = this.applyPepper(password);

      // Verify the password using the specified algorithm
      switch (parsed.alg) {
        case this.algorithms.BCRYPT:
          return await this.verifyWithBcrypt(pepperedPassword, parsed.hash);

        case this.algorithms.ARGON2:
          return await this.verifyWithArgon2(pepperedPassword, parsed.hash);

        case this.algorithms.PBKDF2:
          return await this.verifyWithPbkdf2(
            pepperedPassword,
            parsed.hash,
            parsed.salt,
            parsed.iterations
          );

        default:
          throw new Error(`Unsupported hashing algorithm: ${parsed.alg}`);
      }
    } catch (error) {
      logger.error('Failed to verify password', { error });
      return false;
    }
  }

  /**
   * Check if a hash needs to be upgraded
   * @param hashedPassword Hashed password with metadata
   * @returns Whether the hash needs to be upgraded
   */
  needsUpgrade(hashedPassword: string): boolean {
    try {
      // Parse hashed password
      const parsed = JSON.parse(hashedPassword);

      // Check version
      if (parsed.v !== 1) {
        return true;
      }

      // Check algorithm (prefer bcrypt)
      if (parsed.alg !== this.algorithms.BCRYPT) {
        return true;
      }

      // Check cost factor
      if (parsed.cost < this.defaultCost) {
        return true;
      }

      return false;
    } catch (error) {
      logger.error('Failed to check if hash needs upgrade', { error });
      return true;
    }
  }

  /**
   * Apply pepper to a password
   * @param password Plain text password
   * @returns Peppered password
   */
  private applyPepper(password: string): string {
    if (!this.pepper) {
      return password;
    }

    // Create HMAC using pepper as key
    const hmac = crypto.createHmac('sha256', this.pepper);
    hmac.update(password);
    return hmac.digest('hex');
  }

  /**
   * Hash a password with bcrypt
   * @param password Plain text password
   * @param cost Cost factor
   * @returns Hashed password
   */
  private async hashWithBcrypt(password: string, cost: number): Promise<string> {
    // Generate salt
    const salt = await bcrypt.genSalt(cost);

    // Hash password
    return await bcrypt.hash(password, salt);
  }

  /**
   * Verify a password with bcrypt
   * @param password Plain text password
   * @param hash Hashed password
   * @returns Whether the password matches
   */
  private async verifyWithBcrypt(password: string, hash: string): Promise<boolean> {
    return await bcrypt.compare(password, hash);
  }

  /**
   * Hash a password with Argon2
   * @param password Plain text password
   * @returns Hashed password
   */
  private async hashWithArgon2(_password: string): Promise<string> {
    // Argon2 is not included in Node.js core
    // This is a placeholder for actual implementation
    // In a real implementation, you would use the argon2 package
    throw new Error('Argon2 hashing not implemented');
  }

  /**
   * Verify a password with Argon2
   * @param _password Plain text password
   * @param _hash Hashed password
   * @returns Whether the password matches
   */
  private async verifyWithArgon2(_password: string, _hash: string): Promise<boolean> {
    // Argon2 is not included in Node.js core
    // This is a placeholder for actual implementation
    throw new Error('Argon2 verification not implemented');
  }

  /**
   * Hash a password with PBKDF2
   * @param password Plain text password
   * @returns Hashed password, salt, and iterations
   */
  private async hashWithPbkdf2(
    password: string
  ): Promise<{ hash: string; salt: string; iterations: number }> {
    // Generate random salt
    const salt = crypto.randomBytes(16).toString('hex');

    // Set iterations (higher is more secure but slower)
    const iterations = 100000;

    // Hash password
    const hash = await new Promise<string>((resolve, reject) => {
      crypto.pbkdf2(password, salt, iterations, 64, 'sha512', (err, derivedKey) => {
        if (err) reject(err);
        resolve(derivedKey.toString('hex'));
      });
    });

    return { hash, salt, iterations };
  }

  /**
   * Verify a password with PBKDF2
   * @param password Plain text password
   * @param hash Hashed password
   * @param salt Salt
   * @param iterations Iterations
   * @returns Whether the password matches
   */
  private async verifyWithPbkdf2(
    password: string,
    hash: string,
    salt: string,
    iterations: number
  ): Promise<boolean> {
    // Hash password with same salt and iterations
    const verifyHash = await new Promise<string>((resolve, reject) => {
      crypto.pbkdf2(password, salt, iterations, 64, 'sha512', (err, derivedKey) => {
        if (err) reject(err);
        resolve(derivedKey.toString('hex'));
      });
    });

    // Compare hashes (constant time comparison)
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(verifyHash, 'hex'));
  }

  /**
   * Generate a secure random password
   * @param length Password length
   * @param options Password options
   * @returns Secure random password
   */
  generatePassword(length = 16, options: PasswordGenerationOptions = {}): string {
    const {
      includeLowercase = true,
      includeUppercase = true,
      includeNumbers = true,
      includeSymbols = true,
    } = options;

    // Define character sets
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    // Build character set
    let charset = '';
    if (includeLowercase) charset += lowercase;
    if (includeUppercase) charset += uppercase;
    if (includeNumbers) charset += numbers;
    if (includeSymbols) charset += symbols;

    // Ensure at least one character set is selected
    if (charset.length === 0) {
      charset = lowercase;
    }

    // Generate password
    let password = '';
    const randomBytes = crypto.randomBytes(length * 2);

    // randomBytes will always be defined, but TypeScript needs this check
    if (!randomBytes) {
      throw new Error('Failed to generate random bytes');
    }

    for (let i = 0; i < length; i++) {
      // Use a non-null assertion since we've checked randomBytes is defined
      const randomIndex = randomBytes[i]! % charset.length;
      password += charset[randomIndex];
    }

    return password;
  }

  /**
   * Check password strength
   * @param password Password to check
   * @returns Password strength score (0-100) and feedback
   */
  checkPasswordStrength(password: string): { score: number; feedback: string[] } {
    const feedback: string[] = [];
    let score = 0;

    // Check length
    if (password.length < 8) {
      feedback.push('Password is too short');
    } else if (password.length >= 12) {
      score += 25;
    } else {
      score += 10;
    }

    // Check character types
    if (/[a-z]/.test(password)) score += 10;
    else feedback.push('Add lowercase letters');

    if (/[A-Z]/.test(password)) score += 10;
    else feedback.push('Add uppercase letters');

    if (/[0-9]/.test(password)) score += 10;
    else feedback.push('Add numbers');

    if (/[^A-Za-z0-9]/.test(password)) score += 10;
    else feedback.push('Add special characters');

    // Check complexity
    const uniqueChars = new Set(password.split('')).size;
    score += Math.min(20, uniqueChars * 2);

    // Check common patterns
    if (/(.)\1{2,}/.test(password)) {
      score -= 10;
      feedback.push('Avoid repeated characters');
    }

    if (/^(?:123456|password|qwerty)/i.test(password)) {
      score -= 20;
      feedback.push('Avoid common passwords');
    }

    // Normalize score
    score = Math.max(0, Math.min(100, score));

    // Add strength feedback
    if (score < 40) {
      feedback.unshift('Weak password');
    } else if (score < 70) {
      feedback.unshift('Moderate password');
    } else {
      feedback.unshift('Strong password');
    }

    return { score, feedback };
  }
}

// Export singleton instance
export const passwordHasher = new PasswordHasher();
