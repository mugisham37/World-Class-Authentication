import * as crypto from 'crypto';
// Removed unused import
import { logger } from '../../logging/logger';
import { securityConfig } from '../../../config/security-config';

/**
 * Encryption Service
 * Implements secure data encryption and decryption with key management
 */
class Encryption {
  // Default encryption algorithm
  private readonly defaultAlgorithm: string;

  // Default key derivation iterations
  private readonly defaultIterations: number;

  // Master encryption key
  private readonly masterKey: Buffer;

  // Initialization vector length
  private readonly ivLength: number = 16; // 128 bits

  // Salt length for key derivation
  private readonly saltLength: number = 32; // 256 bits

  // Supported encryption algorithms
  private readonly algorithms = {
    AES_256_GCM: 'aes-256-gcm', // AES-256 in GCM mode (authenticated encryption)
    AES_256_CBC: 'aes-256-cbc', // AES-256 in CBC mode
    AES_192_GCM: 'aes-192-gcm', // AES-192 in GCM mode
    AES_192_CBC: 'aes-192-cbc', // AES-192 in CBC mode
    CHACHA20: 'chacha20-poly1305', // ChaCha20-Poly1305 (authenticated encryption)
  };

  constructor() {
    this.defaultAlgorithm = securityConfig.encryption.algorithm || this.algorithms.AES_256_GCM;
    this.defaultIterations = securityConfig.encryption.keyDerivationIterations || 100000;

    // Initialize master key
    this.masterKey = this.initializeMasterKey();
  }

  /**
   * Initialize master encryption key
   * @returns Master key buffer
   */
  private initializeMasterKey(): Buffer {
    try {
      // Check if master key is provided in config
      if (securityConfig.encryption.masterKey) {
        // Use provided key (hex encoded)
        return Buffer.from(securityConfig.encryption.masterKey, 'hex');
      } else {
        // Generate a secure random key
        logger.warn('No master encryption key provided, generating a random one');
        logger.warn('This key will be lost when the server restarts');
        logger.warn('For production, set a persistent master key in the configuration');

        // Generate a 256-bit key
        return crypto.randomBytes(32);
      }
    } catch (error) {
      logger.error('Failed to initialize master encryption key', { error });
      throw new Error('Failed to initialize encryption service');
    }
  }

  /**
   * Encrypt data
   * @param data Data to encrypt
   * @param options Encryption options
   * @returns Encrypted data with metadata
   */
  encrypt(
    data: string | Buffer,
    options: {
      algorithm?: string;
      key?: string | Buffer;
      keyId?: string;
      associatedData?: string | Buffer;
      encoding?: BufferEncoding;
    } = {}
  ): string {
    const {
      algorithm = this.defaultAlgorithm,
      key,
      keyId,
      associatedData,
      encoding = 'utf8',
    } = options;

    try {
      // Convert data to buffer if it's a string
      const dataBuffer = typeof data === 'string' ? Buffer.from(data, encoding) : data;

      // Generate a random salt for key derivation
      const salt = crypto.randomBytes(this.saltLength);

      // Derive encryption key from master key or provided key
      const encryptionKey = this.deriveKey(key || this.masterKey, salt);

      // Generate a random initialization vector
      const iv = crypto.randomBytes(this.ivLength);

      // Create cipher based on algorithm type
      const isAuthenticatedMode = algorithm.includes('gcm') || algorithm.includes('chacha');

      // Create cipher
      const cipher = crypto.createCipheriv(algorithm, encryptionKey, iv);

      // Add associated data if provided (for authenticated encryption modes)
      if (associatedData && isAuthenticatedMode) {
        const aadBuffer =
          typeof associatedData === 'string'
            ? Buffer.from(associatedData, encoding)
            : associatedData;

        // Cast to CipherGCM for authenticated modes
        (cipher as crypto.CipherGCM).setAAD(aadBuffer);
      }

      // Encrypt data
      const encryptedData = Buffer.concat([cipher.update(dataBuffer), cipher.final()]);

      // Get authentication tag (for authenticated encryption modes)
      let authTag: Buffer | null = null;
      if (isAuthenticatedMode) {
        try {
          // Cast to CipherGCM for authenticated modes
          authTag = (cipher as crypto.CipherGCM).getAuthTag();
        } catch (e) {
          // Not an authenticated encryption mode
          authTag = null;
        }
      }

      // Create result object
      const result = {
        v: 1, // Version
        alg: algorithm,
        salt: salt.toString('base64'),
        iv: iv.toString('base64'),
        data: encryptedData.toString('base64'),
        ...(authTag && { tag: authTag.toString('base64') }),
        ...(keyId && { kid: keyId }),
      };

      // Return JSON string
      return JSON.stringify(result);
    } catch (error) {
      logger.error('Failed to encrypt data', { error, algorithm });
      throw new Error('Failed to encrypt data');
    }
  }

  /**
   * Decrypt data
   * @param encryptedData Encrypted data with metadata
   * @param options Decryption options
   * @returns Decrypted data
   */
  decrypt(
    encryptedData: string,
    options: {
      key?: string | Buffer;
      associatedData?: string | Buffer;
      encoding?: BufferEncoding;
      outputEncoding?: BufferEncoding | null;
    } = {}
  ): string | Buffer {
    const { key, associatedData, encoding = 'utf8', outputEncoding = 'utf8' } = options;

    try {
      // Parse encrypted data
      const parsed = JSON.parse(encryptedData);

      // Validate version
      if (parsed.v !== 1) {
        throw new Error(`Unsupported encryption version: ${parsed.v}`);
      }

      // Extract components
      const {
        alg: algorithm,
        salt: saltBase64,
        iv: ivBase64,
        data: dataBase64,
        tag: tagBase64,
      } = parsed;

      // Convert components to buffers
      const salt = Buffer.from(saltBase64, 'base64');
      const iv = Buffer.from(ivBase64, 'base64');
      const encryptedBuffer = Buffer.from(dataBase64, 'base64');
      const authTag = tagBase64 ? Buffer.from(tagBase64, 'base64') : null;

      // Derive decryption key from master key or provided key
      const decryptionKey = this.deriveKey(key || this.masterKey, salt);

      // Create decipher based on algorithm type
      const isAuthenticatedMode = algorithm.includes('gcm') || algorithm.includes('chacha');

      // Create decipher
      const decipher = crypto.createDecipheriv(algorithm, decryptionKey, iv);

      // Set authentication tag if available for authenticated modes
      if (authTag && isAuthenticatedMode) {
        (decipher as crypto.DecipherGCM).setAuthTag(authTag);
      }

      // Add associated data if provided (for authenticated encryption modes)
      if (associatedData && isAuthenticatedMode) {
        const aadBuffer =
          typeof associatedData === 'string'
            ? Buffer.from(associatedData, encoding)
            : associatedData;
        (decipher as crypto.DecipherGCM).setAAD(aadBuffer);
      }

      // Decrypt data
      const decryptedBuffer = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);

      // Return result in requested format
      return outputEncoding ? decryptedBuffer.toString(outputEncoding) : decryptedBuffer;
    } catch (error) {
      logger.error('Failed to decrypt data', { error });
      throw new Error('Failed to decrypt data');
    }
  }

  /**
   * Derive a key from a password or master key
   * @param key Password or master key
   * @param salt Salt for key derivation
   * @returns Derived key
   */
  private deriveKey(key: string | Buffer, salt: Buffer): Buffer {
    try {
      // Convert key to buffer if it's a string
      const keyBuffer = typeof key === 'string' ? Buffer.from(key, 'utf8') : key;

      // Use PBKDF2 for key derivation
      return crypto.pbkdf2Sync(
        keyBuffer,
        salt,
        this.defaultIterations,
        32, // 256 bits
        'sha512'
      );
    } catch (error) {
      logger.error('Failed to derive key', { error });
      throw new Error('Failed to derive encryption key');
    }
  }

  /**
   * Generate a secure random encryption key
   * @param length Key length in bytes
   * @returns Hex-encoded key
   */
  generateKey(length = 32): string {
    try {
      return crypto.randomBytes(length).toString('hex');
    } catch (error) {
      logger.error('Failed to generate encryption key', { error });
      throw new Error('Failed to generate encryption key');
    }
  }

  /**
   * Hash a value with SHA-256
   * @param value Value to hash
   * @returns Hex-encoded hash
   */
  hash(value: string | Buffer): string {
    try {
      const hash = crypto.createHash('sha256');
      hash.update(value);
      return hash.digest('hex');
    } catch (error) {
      logger.error('Failed to hash value', { error });
      throw new Error('Failed to hash value');
    }
  }

  /**
   * Create a HMAC signature
   * @param value Value to sign
   * @param key Secret key
   * @returns Hex-encoded HMAC
   */
  hmac(value: string | Buffer, key: string | Buffer): string {
    try {
      const hmac = crypto.createHmac('sha256', key);
      hmac.update(value);
      return hmac.digest('hex');
    } catch (error) {
      logger.error('Failed to create HMAC', { error });
      throw new Error('Failed to create HMAC');
    }
  }

  /**
   * Sign data with HMAC
   * @param data Data to sign
   * @param key Secret key
   * @returns Hex-encoded HMAC signature
   */
  hmacSign(data: string | Buffer, key: string | Buffer): string {
    try {
      return this.hmac(data, key);
    } catch (error) {
      logger.error('Failed to create HMAC signature', { error });
      throw new Error('Failed to create HMAC signature');
    }
  }

  /**
   * Verify HMAC signature
   * @param data Original data
   * @param signature HMAC signature to verify
   * @param key Secret key
   * @returns True if signature is valid
   */
  hmacVerify(data: string | Buffer, signature: string, key: string | Buffer): boolean {
    try {
      const expectedSignature = this.hmac(data, key);
      return this.constantTimeEqual(signature, expectedSignature);
    } catch (error) {
      logger.error('Failed to verify HMAC signature', { error });
      return false;
    }
  }

  /**
   * Compare two strings in constant time
   * @param a First string
   * @param b Second string
   * @returns Whether the strings are equal
   */
  private constantTimeEqual(a: string, b: string): boolean {
    try {
      const bufA = Buffer.from(a);
      const bufB = Buffer.from(b);

      if (bufA.length !== bufB.length) {
        return false;
      }

      return crypto.timingSafeEqual(bufA, bufB);
    } catch {
      return false;
    }
  }

  /**
   * Encrypt a value for storage in a database
   * @param value Value to encrypt
   * @param context Context information (e.g., table name, column name)
   * @returns Encrypted value
   */
  encryptForStorage(value: string, context: string): string {
    try {
      // Use context as associated data for additional security
      return this.encrypt(value, { associatedData: context });
    } catch (error) {
      logger.error('Failed to encrypt value for storage', { error, context });
      throw new Error('Failed to encrypt value for storage');
    }
  }

  /**
   * Decrypt a value from storage
   * @param encryptedValue Encrypted value
   * @param context Context information (e.g., table name, column name)
   * @returns Decrypted value
   */
  decryptFromStorage(encryptedValue: string, context: string): string {
    try {
      // Use context as associated data for additional security
      return this.decrypt(encryptedValue, { associatedData: context }) as string;
    } catch (error) {
      logger.error('Failed to decrypt value from storage', { error, context });
      throw new Error('Failed to decrypt value from storage');
    }
  }

  /**
   * Encrypt a value for transmission
   * @param value Value to encrypt
   * @param recipientPublicKey Recipient's public key
   * @returns Encrypted value
   */
  encryptForTransmission(value: string, recipientPublicKey: string): string {
    try {
      // Generate a random symmetric key
      const symmetricKey = crypto.randomBytes(32);

      // Encrypt the value with the symmetric key
      const encryptedValue = this.encrypt(value, { key: symmetricKey });

      // Encrypt the symmetric key with the recipient's public key
      const publicKey = crypto.createPublicKey(recipientPublicKey);
      const encryptedKey = crypto.publicEncrypt(
        {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        symmetricKey
      );

      // Create result object
      const result = {
        v: 1, // Version
        key: encryptedKey.toString('base64'),
        data: encryptedValue,
      };

      // Return JSON string
      return JSON.stringify(result);
    } catch (error) {
      logger.error('Failed to encrypt value for transmission', { error });
      throw new Error('Failed to encrypt value for transmission');
    }
  }

  /**
   * Decrypt a value from transmission
   * @param encryptedValue Encrypted value
   * @param privateKey Private key
   * @returns Decrypted value
   */
  decryptFromTransmission(encryptedValue: string, privateKey: string): string {
    try {
      // Parse encrypted data
      const parsed = JSON.parse(encryptedValue);

      // Validate version
      if (parsed.v !== 1) {
        throw new Error(`Unsupported encryption version: ${parsed.v}`);
      }

      // Extract components
      const { key: encryptedKeyBase64, data: encryptedData } = parsed;

      // Convert components to buffers
      const encryptedKey = Buffer.from(encryptedKeyBase64, 'base64');

      // Decrypt the symmetric key with the private key
      const key = crypto.createPrivateKey(privateKey);
      const symmetricKey = crypto.privateDecrypt(
        {
          key,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        encryptedKey
      );

      // Decrypt the value with the symmetric key
      return this.decrypt(encryptedData, { key: symmetricKey }) as string;
    } catch (error) {
      logger.error('Failed to decrypt value from transmission', { error });
      throw new Error('Failed to decrypt value from transmission');
    }
  }
}

// Export singleton instance
export const encryption = new Encryption();
