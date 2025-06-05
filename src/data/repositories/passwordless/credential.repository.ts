import { Credential, CertificateChallenge, CertificateCredential, MagicLink, MagicLinkData } from "../../../core/passwordless/types";

/**
 * OTP credential interface
 */
export interface OtpCredential {
  id: string;
  userId: string;
  destination: string;
  code: string;
  type: string;
  expiresAt: Date;
  attempts: number;
  maxAttempts: number;
  metadata: Record<string, any>;
}

/**
 * Repository for passwordless credentials
 */
export interface PasswordlessCredentialRepository {
  /**
   * Find credential by ID
   * @param id Credential ID
   */
  findById(id: string): Promise<Credential | null>;
  
  /**
   * Find credentials by user ID
   * @param userId User ID
   */
  findByUserId(userId: string): Promise<Credential[]>;
  
  /**
   * Create a new credential
   * @param data Credential data
   */
  create(data: Partial<Credential>): Promise<Credential>;
  
  /**
   * Delete a credential
   * @param id Credential ID
   */
  delete(id: string): Promise<void>;

  /**
   * Store a certificate challenge
   * @param data Certificate challenge data
   */
  storeCertificateChallenge(data: {
    id: string;
    userId: string;
    challenge: string;
    type: string;
    expiresAt: Date;
    metadata: Record<string, any>;
  }): Promise<void>;
  
  /**
   * Find a certificate challenge by ID
   * @param id Challenge ID
   */
  findCertificateChallengeById(id: string): Promise<CertificateChallenge | null>;
  
  /**
   * Store a certificate credential
   * @param data Certificate credential data
   */
  storeCertificateCredential(data: {
    id: string;
    userId: string;
    certificate: string;
    subject: string;
    issuer: string;
    serialNumber: string;
    validFrom: Date;
    validTo: Date;
    fingerprint: string;
    createdAt: Date;
    lastUsedAt: Date | null;
    metadata: Record<string, any>;
  }): Promise<void>;
  
  /**
   * Find certificate credentials by user ID
   * @param userId User ID
   */
  findCertificateCredentialsByUserId(userId: string): Promise<CertificateCredential[]>;
  
  /**
   * Find a certificate credential by fingerprint
   * @param fingerprint Certificate fingerprint
   */
  findCertificateCredentialByFingerprint(fingerprint: string): Promise<CertificateCredential | null>;
  
  /**
   * Find a certificate credential by ID
   * @param id Credential ID
   */
  findCertificateCredentialById(id: string): Promise<CertificateCredential | null>;
  
  /**
   * Update a certificate credential
   * @param id Credential ID
   * @param data Updated credential data
   */
  updateCertificateCredential(id: string, data: Partial<CertificateCredential>): Promise<void>;
  
  /**
   * Delete a certificate credential
   * @param id Credential ID
   */
  deleteCertificateCredential(id: string): Promise<boolean>;
  
  /**
   * Find WebAuthn credentials by user ID
   * @param userId User ID
   */
  findWebAuthnCredentialsByUserId(userId: string): Promise<any[]>;
  
  /**
   * Find a WebAuthn credential by credential ID
   * @param credentialId Credential ID
   */
  findWebAuthnCredentialByCredentialId(credentialId: string): Promise<any>;
  
  /**
   * Store a WebAuthn credential
   * @param data WebAuthn credential data
   */
  storeWebAuthnCredential(data: any): Promise<any>;
  
  /**
   * Update a WebAuthn credential
   * @param id Credential ID
   * @param data Updated credential data
   */
  updateWebAuthnCredential(id: string, data: Partial<any>): Promise<void>;
  
  /**
   * Delete a WebAuthn credential
   * @param id Credential ID
   */
  deleteWebAuthnCredential(id: string): Promise<boolean>;
  
  /**
   * Find active magic links by user ID
   * @param userId User ID
   */
  findActiveMagicLinksByUserId(userId: string): Promise<MagicLink[]>;
  
  /**
   * Find a magic link by ID
   * @param id Magic link ID
   */
  findMagicLinkById(id: string): Promise<MagicLink | null>;
  
  /**
   * Store a magic link
   * @param data Magic link data
   */
  storeMagicLink(data: MagicLinkData): Promise<void>;
  
  /**
   * Update a magic link
   * @param id Magic link ID
   * @param data Updated magic link data
   */
  updateMagicLink(id: string, data: Partial<MagicLink>): Promise<void>;
  
  /**
   * Store an OTP credential
   * @param data OTP credential data
   */
  storeOtp(data: {
    id: string;
    userId: string;
    destination: string;
    code: string;
    type: string;
    expiresAt: Date;
    attempts: number;
    maxAttempts: number;
    metadata: Record<string, any>;
  }): Promise<void>;
  
  /**
   * Find an OTP credential by ID
   * @param id OTP ID
   */
  findOtpById(id: string): Promise<OtpCredential | null>;
  
  /**
   * Update an OTP credential
   * @param id OTP ID
   * @param data Updated OTP data
   */
  updateOtp(id: string, data: Partial<{
    attempts: number;
    metadata: Record<string, any>;
  }>): Promise<void>;
}
