/**
 * Types for passwordless authentication
 */

/**
 * Magic link interface
 */
export interface MagicLink {
  id: string;
  userId: string;
  email: string;
  token: string;
  expiresAt: Date;
  used: boolean;
  createdAt: Date;
  metadata: Record<string, any>;
}

/**
 * Magic link data for creation
 */
export interface MagicLinkData extends Omit<MagicLink, 'createdAt'> {
  metadata: Record<string, any>;
}

/**
 * Authentication or registration challenge
 */
export interface Challenge {
  id: string;
  expiresAt: Date;
  metadata: Record<string, any>;
  clientData?: Record<string, any>;
}

/**
 * Certificate challenge for certificate-based authentication
 */
export interface CertificateChallenge {
  id: string;
  userId: string;
  challenge: string;
  type: 'registration' | 'authentication';
  expiresAt: Date;
  metadata: {
    ipAddress?: string;
    userAgent?: string;
    origin?: string;
  };
}

/**
 * Result of verification process
 */
export interface VerificationResult {
  success: boolean;
  reason?: string;
  message?: string;
  token?: string;
}

/**
 * Passwordless credential
 */
export interface Credential {
  id: string;
  type: string;
  name: string;
  createdAt: Date;
  userId: string;
  metadata?: {
    lastUsed?: Date;
    [key: string]: any;
  };
}

/**
 * Certificate credential for certificate-based authentication
 */
export interface CertificateCredential {
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
  metadata: {
    ipAddress?: string;
    userAgent?: string;
    origin?: string;
    [key: string]: any;
  };
}

/**
 * User model interface
 */
import { BaseUser } from "../../shared/types/user.types";

export interface User extends BaseUser {
  // Add any passwordless-specific user properties here if needed
}
