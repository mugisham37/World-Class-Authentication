import { WebAuthnOptions } from '../interfaces';
import { BadRequestError } from '../../../utils/error-handling';

/**
 * Validates WebAuthn options to ensure they conform to the expected types
 * @param options WebAuthn options to validate
 * @throws BadRequestError if options are invalid
 */
export function validateWebAuthnOptions(options: Partial<WebAuthnOptions>): void {
  // Define valid values for enum properties
  const validUserVerification = ['required', 'preferred', 'discouraged'];
  const validAuthenticatorAttachment = ['platform', 'cross-platform'];
  const validAttestation = ['none', 'indirect', 'direct'];

  // Validate userVerification
  if (options.userVerification && !validUserVerification.includes(options.userVerification)) {
    throw new BadRequestError(
      `Invalid userVerification value. Must be one of: ${validUserVerification.join(', ')}`
    );
  }

  // Validate authenticatorAttachment
  if (
    options.authenticatorAttachment &&
    !validAuthenticatorAttachment.includes(options.authenticatorAttachment)
  ) {
    throw new BadRequestError(
      `Invalid authenticatorAttachment value. Must be one of: ${validAuthenticatorAttachment.join(', ')}`
    );
  }

  // Validate attestation
  if (options.attestation && !validAttestation.includes(options.attestation)) {
    throw new BadRequestError(
      `Invalid attestation value. Must be one of: ${validAttestation.join(', ')}`
    );
  }

  // Validate timeout
  if (
    options.timeout !== undefined &&
    (typeof options.timeout !== 'number' || options.timeout <= 0)
  ) {
    throw new BadRequestError('Timeout must be a positive number');
  }

  // Validate requireResidentKey
  if (options.requireResidentKey !== undefined && typeof options.requireResidentKey !== 'boolean') {
    throw new BadRequestError('requireResidentKey must be a boolean');
  }
}

/**
 * Creates a WebAuthnOptions object with default values from config
 * @param options Partial WebAuthnOptions to merge with defaults
 * @param type Type of operation (authentication or registration)
 * @returns WebAuthnOptions with defaults applied
 */
export function createWebAuthnOptions(
  options: Partial<WebAuthnOptions> = {},
  type: 'authentication' | 'registration' = 'authentication'
): WebAuthnOptions {
  // Import here to avoid circular dependency
  const { passwordlessConfig } = require('../passwordless.config');

  // Create options with defaults from config
  const webAuthnOptions: WebAuthnOptions = {
    userVerification: passwordlessConfig.biometric.userVerification,
    authenticatorAttachment: passwordlessConfig.biometric.authenticatorAttachment,
    timeout: passwordlessConfig.biometric.timeout,
    attestation: passwordlessConfig.biometric.attestation,
    requireResidentKey: passwordlessConfig.biometric.requireResidentKey,
    ...options,
  };

  // Validate the options
  validateWebAuthnOptions(webAuthnOptions);

  return webAuthnOptions;
}
