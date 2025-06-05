/**
 * WebAuthn options interface
 * Represents options for WebAuthn operations
 */
export interface WebAuthnOptions {
  requireResidentKey?: boolean;
  origin?: string;
  challenge?: string;
  userId?: string;
  deviceType?: string;
  deviceName?: string;
  ipAddress?: string;
  userAgent?: string;
  userVerification?: 'required' | 'preferred' | 'discouraged';
  authenticatorAttachment?: 'platform' | 'cross-platform';
  timeout?: number;
  attestation?: 'none' | 'indirect' | 'direct';
}
