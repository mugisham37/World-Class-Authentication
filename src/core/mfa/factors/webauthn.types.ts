/**
 * WebAuthn specific types and interfaces
 */

/**
 * Interface for WebAuthn authenticator data
 */
export interface WebAuthnAuthenticatorData {
  credentialID: Buffer;
  credentialPublicKey: Buffer;
  counter: number;
}

/**
 * Interface for WebAuthn verification result
 */
export interface WebAuthnVerificationResult {
  verified: boolean;
  authenticationInfo: {
    newCounter: number;
  };
}

/**
 * Custom error class for WebAuthn verification errors
 */
export class WebAuthnVerificationError extends Error {
  constructor(
    message: string,
    public readonly details: Record<string, any>
  ) {
    super(message);
    this.name = 'WebAuthnVerificationError';
  }
}

/**
 * Enum for WebAuthn verification error types
 */
export enum WebAuthnErrorType {
  INVALID_CHALLENGE = 'invalid_challenge',
  INVALID_FACTOR = 'invalid_factor',
  VERIFICATION_FAILED = 'verification_failed',
  REPLAY_ATTACK = 'replay_attack',
  INTERNAL_ERROR = 'internal_error',
}
