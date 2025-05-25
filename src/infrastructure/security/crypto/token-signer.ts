import * as crypto from 'crypto';
import { securityConfig } from '../../../config/security-config';
import { logger } from '../../logging/logger';

// Add type definitions for better type safety
type SigningAlgorithm =
  | 'HS256'
  | 'HS384'
  | 'HS512'
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'ES256'
  | 'ES384'
  | 'ES512';

interface KeyPair {
  publicKey: string;
  privateKey: string;
}

/**
 * Token Signer Service
 * Implements secure token signing and verification with multiple algorithms
 */
export class TokenSigner {
  // Default signing algorithm
  private readonly defaultAlgorithm: SigningAlgorithm;

  // Key pairs for asymmetric algorithms
  private readonly keyPairs: Map<string, KeyPair> = new Map();

  // Secret keys for symmetric algorithms
  private readonly secretKeys: Map<string, string> = new Map();

  // Supported signing algorithms with proper typing
  private readonly algorithms: Record<SigningAlgorithm, SigningAlgorithm> = {
    HS256: 'HS256', // HMAC with SHA-256
    HS384: 'HS384', // HMAC with SHA-384
    HS512: 'HS512', // HMAC with SHA-512
    RS256: 'RS256', // RSASSA-PKCS1-v1_5 with SHA-256
    RS384: 'RS384', // RSASSA-PKCS1-v1_5 with SHA-384
    RS512: 'RS512', // RSASSA-PKCS1-v1_5 with SHA-512
    ES256: 'ES256', // ECDSA with P-256 and SHA-256
    ES384: 'ES384', // ECDSA with P-384 and SHA-384
    ES512: 'ES512', // ECDSA with P-521 and SHA-512
  } as const;

  constructor() {
    // Set default algorithm
    this.defaultAlgorithm = this.algorithms.HS256;

    // Initialize keys
    this.initializeKeys();
  }

  /**
   * Initialize signing keys
   */
  private initializeKeys(): void {
    try {
      // Initialize secret keys for symmetric algorithms
      this.initializeSecretKeys();

      // Initialize key pairs for asymmetric algorithms
      this.initializeKeyPairs();
    } catch (error) {
      logger.error('Failed to initialize signing keys', { error });
      throw new Error('Failed to initialize token signer');
    }
  }

  /**
   * Initialize secret keys for symmetric algorithms
   */
  private initializeSecretKeys(): void {
    // Use configured secret key or generate a random one
    const secretKey = securityConfig.jwt.accessTokenSecret || this.generateSecretKey();

    // Store secret keys for different algorithms
    this.secretKeys.set(this.algorithms.HS256, secretKey);
    this.secretKeys.set(this.algorithms.HS384, secretKey);
    this.secretKeys.set(this.algorithms.HS512, secretKey);

    logger.debug('Secret keys initialized for symmetric algorithms');
  }

  /**
   * Initialize key pairs for asymmetric algorithms
   */
  private initializeKeyPairs(): void {
    // In a real implementation, key pairs would be loaded from config
    // For now, we'll generate them on demand

    // Generate key pairs for algorithms that don't have them
    this.generateMissingKeyPairs();

    logger.debug('Key pairs initialized for asymmetric algorithms');
  }

  /**
   * Generate missing key pairs
   */
  private generateMissingKeyPairs(): void {
    // Generate RSA key pairs
    if (!this.keyPairs.has(this.algorithms.RS256)) {
      const keyPair = this.generateRsaKeyPair();
      this.keyPairs.set(this.algorithms.RS256, keyPair);
      this.keyPairs.set(this.algorithms.RS384, keyPair);
      this.keyPairs.set(this.algorithms.RS512, keyPair);
    }

    // Generate EC key pairs
    if (!this.keyPairs.has(this.algorithms.ES256)) {
      this.keyPairs.set(this.algorithms.ES256, this.generateEcKeyPair('prime256v1'));
    }

    if (!this.keyPairs.has(this.algorithms.ES384)) {
      this.keyPairs.set(this.algorithms.ES384, this.generateEcKeyPair('secp384r1'));
    }

    if (!this.keyPairs.has(this.algorithms.ES512)) {
      this.keyPairs.set(this.algorithms.ES512, this.generateEcKeyPair('secp521r1'));
    }
  }

  /**
   * Generate a random secret key
   * @returns Random secret key
   */
  private generateSecretKey(): string {
    return crypto.randomBytes(64).toString('hex');
  }

  /**
   * Generate an RSA key pair
   * @returns RSA key pair
   */
  private generateRsaKeyPair(): KeyPair {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    return { publicKey, privateKey };
  }

  /**
   * Generate an EC key pair
   * @param curve Elliptic curve name
   * @returns EC key pair
   */
  private generateEcKeyPair(curve: string): KeyPair {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: curve,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    return { publicKey, privateKey };
  }

  /**
   * Parse a timespan string or number to seconds
   * @param timespan Timespan string or number
   * @returns Timespan in seconds
   */
  private parseTimespan(timespan: number | string | undefined): number {
    if (!timespan) {
      return 0;
    }

    if (typeof timespan === 'number') {
      return timespan;
    }

    const match = timespan.match(/^(\d+)([smhd])$/);
    if (!match || !match[1] || !match[2]) {
      throw new Error(`Invalid timespan format: ${timespan}`);
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
      case 's':
        return value;
      case 'm':
        return value * 60;
      case 'h':
        return value * 60 * 60;
      case 'd':
        return value * 60 * 60 * 24;
      default:
        throw new Error(`Invalid timespan unit: ${unit}`);
    }
  }

  /**
   * Base64URL encode a string or buffer
   * @param input String or buffer to encode
   * @returns Base64URL-encoded string
   */
  private base64UrlEncode(input: string | Buffer): string {
    let base64: string;
    if (Buffer.isBuffer(input)) {
      base64 = input.toString('base64');
    } else {
      base64 = Buffer.from(input).toString('base64');
    }

    // Convert to base64url format
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /**
   * Base64URL decode a string - FIXED VERSION
   * @param input Base64URL-encoded string
   * @param encoding Output encoding
   * @returns Decoded string or buffer
   */
  private base64UrlDecode(
    input: string | undefined,
    encoding: BufferEncoding | 'binary' = 'utf8'
  ): string | Buffer {
    if (!input) {
      throw new Error('Input is required for base64URL decoding');
    }

    try {
      // Convert from base64url format
      let base64 = input.replace(/-/g, '+').replace(/_/g, '/');

      // Add padding if needed
      while (base64.length % 4) {
        base64 += '=';
      }

      if (encoding === 'binary') {
        return Buffer.from(base64, 'base64');
      }

      return Buffer.from(base64, 'base64').toString(encoding);
    } catch (error) {
      throw new Error('Invalid base64URL encoding');
    }
  }

  /**
   * Compare two strings in constant time
   * @param a First string
   * @param b Second string
   * @returns Whether the strings are equal
   */
  private constantTimeEqual(a: string, b: string): boolean {
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);

    // Return false if lengths are different
    if (bufA.length !== bufB.length) {
      return false;
    }

    // Use timing-safe comparison
    return crypto.timingSafeEqual(bufA, bufB);
  }

  /**
   * Get the hash algorithm for a signing algorithm
   * @param algorithm Signing algorithm
   * @returns Hash algorithm
   */
  private getHashAlgorithm(algorithm: string): string {
    switch (algorithm) {
      case this.algorithms.HS256:
      case this.algorithms.RS256:
      case this.algorithms.ES256:
        return 'sha256';
      case this.algorithms.HS384:
      case this.algorithms.RS384:
      case this.algorithms.ES384:
        return 'sha384';
      case this.algorithms.HS512:
      case this.algorithms.RS512:
      case this.algorithms.ES512:
        return 'sha512';
      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  /**
   * Get a key pair for an algorithm - FIXED VERSION
   * @param algorithm Signing algorithm
   * @param keyId Key ID (optional)
   * @returns Key pair
   */
  private getKeyPair(algorithm: string, keyId?: string | undefined): KeyPair {
    // Ensure keyId is a string, default to empty string if undefined
    const finalKeyId = keyId || '';

    // If key ID is provided and not empty, try to find the key pair
    if (finalKeyId.length > 0) {
      const keyPair = this.keyPairs.get(finalKeyId);
      if (keyPair) {
        return keyPair;
      }
    }

    // Otherwise, use the algorithm's default key pair
    const keyPair = this.keyPairs.get(algorithm);
    if (!keyPair) {
      throw new Error(`Key pair not found for algorithm: ${algorithm}`);
    }

    return keyPair;
  }

  /**
   * Sign a payload
   * @param payload Payload to sign
   * @param options Signing options
   * @returns Signed token
   */
  sign(
    payload: Record<string, any>,
    options: {
      algorithm?: string;
      expiresIn?: number | string;
      notBefore?: number | string;
      audience?: string | string[];
      issuer?: string;
      subject?: string;
      jwtId?: string;
      keyId?: string;
    } = {}
  ): string {
    const {
      algorithm = this.defaultAlgorithm,
      expiresIn,
      notBefore,
      audience,
      issuer = securityConfig.jwt.issuer || 'auth-service',
      subject,
      jwtId = crypto.randomBytes(16).toString('hex'),
      keyId,
    } = options;

    try {
      // Create header
      const header: Record<string, any> = {
        alg: algorithm,
        typ: 'JWT',
      };

      // Add key ID if provided
      if (keyId) {
        header['kid'] = keyId;
      }

      // Create claims
      const now = Math.floor(Date.now() / 1000);
      const claims: Record<string, any> = {
        ...payload,
        iat: now, // Issued at
        jti: jwtId, // JWT ID
      };

      // Add optional claims
      if (expiresIn) {
        claims['exp'] = now + this.parseTimespan(expiresIn);
      }

      if (notBefore) {
        claims['nbf'] = now + this.parseTimespan(notBefore);
      }

      if (audience) {
        claims['aud'] = audience;
      }

      if (issuer) {
        claims['iss'] = issuer;
      }

      if (subject) {
        claims['sub'] = subject;
      }

      // Encode header and claims
      const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
      const encodedClaims = this.base64UrlEncode(JSON.stringify(claims));

      // Create signature base
      const signatureBase = `${encodedHeader}.${encodedClaims}`;

      // Create signature with proper keyId handling
      const signature = this.createSignature(signatureBase, algorithm, keyId);

      // Return complete token
      return `${signatureBase}.${signature}`;
    } catch (error) {
      logger.error('Failed to sign token', { error, algorithm });
      throw new Error('Failed to sign token');
    }
  }

  /**
   * Verify a token
   * @param token Token to verify
   * @param options Verification options
   * @returns Decoded payload if token is valid
   */
  verify(
    token: string,
    options: {
      algorithms?: string[];
      audience?: string | string[] | undefined;
      issuer?: string | undefined;
      subject?: string | undefined;
      clockTolerance?: number;
      ignoreExpiration?: boolean;
      ignoreNotBefore?: boolean;
    } = {}
  ): Record<string, any> {
    const {
      algorithms = [this.defaultAlgorithm],
      audience,
      issuer,
      subject,
      clockTolerance = 0,
      ignoreExpiration = false,
      ignoreNotBefore = false,
    } = options;

    try {
      // Split token into parts
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid token format');
      }

      const [encodedHeader, encodedClaims, signature] = parts;

      // Decode header with proper error handling
      const headerStr = this.base64UrlDecode(encodedHeader);
      if (typeof headerStr !== 'string') {
        throw new Error('Invalid header encoding');
      }
      const header = JSON.parse(headerStr) as Record<string, any>;

      // Check algorithm
      if (!algorithms.includes(header['alg'] as string)) {
        throw new Error(`Algorithm ${header['alg']} is not allowed`);
      }

      // Verify signature with proper kid handling
      const signatureBase = `${encodedHeader}.${encodedClaims}`;
      const kid = header['kid'] as string | undefined;
      const isValid = this.verifySignature(signatureBase, signature, header['alg'] as string, kid);

      if (!isValid) {
        throw new Error('Invalid signature');
      }

      // Decode claims with proper error handling
      const claimsStr = this.base64UrlDecode(encodedClaims);
      if (typeof claimsStr !== 'string') {
        throw new Error('Invalid claims encoding');
      }
      const claims = JSON.parse(claimsStr) as Record<string, any>;

      // Verify claims
      this.verifyClaims(claims, {
        audience,
        issuer,
        subject,
        clockTolerance,
        ignoreExpiration,
        ignoreNotBefore,
      });

      return claims;
    } catch (error) {
      logger.error('Failed to verify token', { error });
      throw error;
    }
  }

  /**
   * Decode a token without verification - FIXED VERSION
   * @param token Token to decode
   * @returns Decoded header and payload
   */
  decode(token: string): { header: Record<string, any>; payload: Record<string, any> } {
    try {
      // Split token into parts
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid token format');
      }

      const [encodedHeader, encodedClaims] = parts;

      // Decode header and claims with proper null checks
      const headerStr = this.base64UrlDecode(encodedHeader || '');
      const claimsStr = this.base64UrlDecode(encodedClaims || '');

      if (typeof headerStr !== 'string' || typeof claimsStr !== 'string') {
        throw new Error('Invalid token encoding');
      }

      const header = JSON.parse(headerStr) as Record<string, any>;
      const payload = JSON.parse(claimsStr) as Record<string, any>;

      return { header, payload };
    } catch (error) {
      logger.error('Failed to decode token', { error });
      throw new Error('Failed to decode token');
    }
  }

  /**
   * Create a signature - FIXED VERSION
   * @param data Data to sign
   * @param algorithm Signing algorithm
   * @param keyId Key ID (optional)
   * @returns Base64URL-encoded signature
   */
  private createSignature(data: string, algorithm: string, keyId?: string | undefined): string {
    if (!data || !algorithm) {
      throw new Error('Data and algorithm are required for signature creation');
    }

    // Ensure keyId is always a string
    const finalKeyId = keyId || '';

    switch (algorithm) {
      case this.algorithms.HS256:
      case this.algorithms.HS384:
      case this.algorithms.HS512:
        return this.createHmacSignature(data, algorithm);

      case this.algorithms.RS256:
      case this.algorithms.RS384:
      case this.algorithms.RS512:
        return this.createRsaSignature(data, algorithm, finalKeyId);

      case this.algorithms.ES256:
      case this.algorithms.ES384:
      case this.algorithms.ES512:
        return this.createEcdsaSignature(data, algorithm, finalKeyId);

      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  /**
   * Create an HMAC signature
   * @param data Data to sign
   * @param algorithm HMAC algorithm
   * @returns Base64URL-encoded signature
   */
  private createHmacSignature(data: string, algorithm: string): string {
    const secretKey = this.secretKeys.get(algorithm);
    if (!secretKey) {
      throw new Error(`Secret key not found for algorithm: ${algorithm}`);
    }

    const hmacAlgorithm = this.getHashAlgorithm(algorithm);
    const hmac = crypto.createHmac(hmacAlgorithm, secretKey);
    hmac.update(data);
    return this.base64UrlEncode(hmac.digest());
  }

  /**
   * Create an RSA signature - FIXED VERSION
   * @param data Data to sign
   * @param algorithm RSA algorithm
   * @param keyId Key ID
   * @returns Base64URL-encoded signature
   */
  private createRsaSignature(data: string, algorithm: string, keyId: string): string {
    const keyPair = this.getKeyPair(algorithm, keyId);
    const hashAlgorithm = this.getHashAlgorithm(algorithm);

    const sign = crypto.createSign(hashAlgorithm);
    sign.update(data);
    const signature = sign.sign(keyPair.privateKey);

    return this.base64UrlEncode(signature);
  }

  /**
   * Create an ECDSA signature - FIXED VERSION
   * @param data Data to sign
   * @param algorithm ECDSA algorithm
   * @param keyId Key ID
   * @returns Base64URL-encoded signature
   */
  private createEcdsaSignature(data: string, algorithm: string, keyId: string): string {
    const keyPair = this.getKeyPair(algorithm, keyId);
    const hashAlgorithm = this.getHashAlgorithm(algorithm);

    const sign = crypto.createSign(hashAlgorithm);
    sign.update(data);
    const signature = sign.sign(keyPair.privateKey);

    return this.base64UrlEncode(signature);
  }

  /**
   * Verify a signature - FIXED VERSION
   * @param data Signed data
   * @param signature Base64URL-encoded signature
   * @param algorithm Signing algorithm
   * @param keyId Key ID (optional)
   * @returns Whether the signature is valid
   */
  private verifySignature(
    data: string,
    signature: string | undefined,
    algorithm: string,
    keyId?: string | undefined
  ): boolean {
    if (!data || !signature || !algorithm) {
      logger.debug('Invalid input for signature verification', {
        hasData: !!data,
        hasSignature: !!signature,
        algorithm,
      });
      return false;
    }

    // Ensure keyId is always a string
    const finalKeyId = keyId || '';

    try {
      switch (algorithm) {
        case this.algorithms.HS256:
        case this.algorithms.HS384:
        case this.algorithms.HS512:
          return this.verifyHmacSignature(data, signature, algorithm);

        case this.algorithms.RS256:
        case this.algorithms.RS384:
        case this.algorithms.RS512:
          return this.verifyRsaSignature(data, signature, algorithm, finalKeyId);

        case this.algorithms.ES256:
        case this.algorithms.ES384:
        case this.algorithms.ES512:
          return this.verifyEcdsaSignature(data, signature, algorithm, finalKeyId);

        default:
          logger.error(`Unsupported algorithm: ${algorithm}`);
          return false;
      }
    } catch (error) {
      logger.error('Signature verification failed', { error, algorithm });
      return false;
    }
  }

  /**
   * Verify an HMAC signature
   * @param data Signed data
   * @param signature Base64URL-encoded signature
   * @param algorithm HMAC algorithm
   * @returns Whether the signature is valid
   */
  private verifyHmacSignature(data: string, signature: string, algorithm: string): boolean {
    try {
      const expectedSignature = this.createHmacSignature(data, algorithm);
      return this.constantTimeEqual(signature, expectedSignature);
    } catch (error) {
      logger.error('HMAC signature verification failed', { error });
      return false;
    }
  }

  /**
   * Verify an RSA signature - FIXED VERSION
   * @param data Signed data
   * @param signature Base64URL-encoded signature
   * @param algorithm RSA algorithm
   * @param keyId Key ID
   * @returns Whether the signature is valid
   */
  private verifyRsaSignature(
    data: string,
    signature: string,
    algorithm: string,
    keyId: string
  ): boolean {
    if (!data || !signature || !algorithm) {
      return false;
    }

    try {
      const keyPair = this.getKeyPair(algorithm, keyId);
      const hashAlgorithm = this.getHashAlgorithm(algorithm);

      const verify = crypto.createVerify(hashAlgorithm);
      verify.update(data);

      const signatureBuffer = this.base64UrlDecode(signature, 'binary');
      if (Buffer.isBuffer(signatureBuffer)) {
        return verify.verify(keyPair.publicKey, signatureBuffer);
      }

      return false;
    } catch (error) {
      logger.error('RSA signature verification failed', { error });
      return false;
    }
  }

  /**
   * Verify an ECDSA signature - FIXED VERSION
   * @param data Signed data
   * @param signature Base64URL-encoded signature
   * @param algorithm ECDSA algorithm
   * @param keyId Key ID
   * @returns Whether the signature is valid
   */
  private verifyEcdsaSignature(
    data: string,
    signature: string,
    algorithm: string,
    keyId: string
  ): boolean {
    if (!data || !signature || !algorithm) {
      return false;
    }

    try {
      const keyPair = this.getKeyPair(algorithm, keyId);
      const hashAlgorithm = this.getHashAlgorithm(algorithm);

      const verify = crypto.createVerify(hashAlgorithm);
      verify.update(data);

      const signatureBuffer = this.base64UrlDecode(signature, 'binary');
      if (Buffer.isBuffer(signatureBuffer)) {
        return verify.verify(keyPair.publicKey, signatureBuffer);
      }

      return false;
    } catch (error) {
      logger.error('ECDSA signature verification failed', { error });
      return false;
    }
  }

  /**
   * Verify token claims
   * @param claims Token claims
   * @param options Verification options
   */
  private verifyClaims(
    claims: Record<string, any>,
    options: {
      audience?: string | string[] | undefined;
      issuer?: string | undefined;
      subject?: string | undefined;
      clockTolerance?: number;
      ignoreExpiration?: boolean;
      ignoreNotBefore?: boolean;
    }
  ): void {
    const {
      audience,
      issuer,
      subject,
      clockTolerance = 0,
      ignoreExpiration = false,
      ignoreNotBefore = false,
    } = options;

    const now = Math.floor(Date.now() / 1000);

    // Check expiration
    if (!ignoreExpiration && claims['exp'] !== undefined) {
      if (now > claims['exp'] + clockTolerance) {
        throw new Error('Token expired');
      }
    }

    // Check not before
    if (!ignoreNotBefore && claims['nbf'] !== undefined) {
      if (now < claims['nbf'] - clockTolerance) {
        throw new Error('Token not valid yet');
      }
    }

    // Check audience
    if (audience !== undefined && claims['aud'] !== undefined) {
      const audiences = Array.isArray(audience) ? audience : [audience];
      const tokenAudiences = Array.isArray(claims['aud']) ? claims['aud'] : [claims['aud']];

      const matchingAudience = audiences.some(aud => tokenAudiences.includes(aud));
      if (!matchingAudience) {
        throw new Error('Token audience invalid');
      }
    }

    // Check issuer
    if (issuer !== undefined && claims['iss'] !== undefined) {
      if (issuer !== claims['iss']) {
        throw new Error('Token issuer invalid');
      }
    }

    // Check subject
    if (subject !== undefined && claims['sub'] !== undefined) {
      if (subject !== claims['sub']) {
        throw new Error('Token subject invalid');
      }
    }
  }

  /**
   * Generate a refresh token
   * @param userId User ID
   * @param options Token options
   * @returns Refresh token
   */
  generateRefreshToken(
    userId: string,
    options: {
      expiresIn?: number | string;
      sessionId?: string;
      deviceInfo?: Record<string, any>;
    } = {}
  ): string {
    if (!userId) {
      throw new Error('User ID is required for refresh token generation');
    }

    const {
      expiresIn = securityConfig.jwt.refreshTokenExpiresIn || '7d',
      sessionId = crypto.randomBytes(16).toString('hex'),
      deviceInfo = {},
    } = options;

    return this.sign(
      {
        type: 'refresh',
        userId,
        sessionId,
        deviceInfo,
      },
      {
        expiresIn,
        subject: userId,
        jwtId: sessionId,
      }
    );
  }

  /**
   * Generate an access token
   * @param userId User ID
   * @param options Token options
   * @returns Access token
   */
  generateAccessToken(
    userId: string,
    options: {
      expiresIn?: number | string;
      sessionId?: string;
      roles?: string[];
      permissions?: string[];
      metadata?: Record<string, any>;
    } = {}
  ): string {
    if (!userId) {
      throw new Error('User ID is required for access token generation');
    }

    const {
      expiresIn = securityConfig.jwt.accessTokenExpiresIn || '15m',
      sessionId,
      roles = [],
      permissions = [],
      metadata = {},
    } = options;

    return this.sign(
      {
        type: 'access',
        userId,
        roles,
        permissions,
        ...metadata,
      },
      {
        expiresIn,
        subject: userId,
        ...(sessionId ? { jwtId: sessionId } : {}),
      }
    );
  }

  /**
   * Generate a verification token
   * @param userId User ID
   * @param purpose Token purpose
   * @param options Token options
   * @returns Verification token
   */
  generateVerificationToken(
    userId: string,
    purpose: string,
    options: {
      expiresIn?: number | string;
      metadata?: Record<string, any>;
    } = {}
  ): string {
    if (!userId || !purpose) {
      throw new Error('User ID and purpose are required for verification token generation');
    }

    const { expiresIn = '1d', metadata = {} } = options;

    return this.sign(
      {
        type: 'verification',
        purpose,
        userId,
        ...metadata,
      },
      {
        expiresIn,
        subject: userId,
      }
    );
  }
}

// Create and export a singleton instance
export const tokenSigner = new TokenSigner();
