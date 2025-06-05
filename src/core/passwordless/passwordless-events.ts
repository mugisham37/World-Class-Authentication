/**
 * Passwordless authentication event types
 */
export enum PasswordlessEvent {
  // WebAuthn events
  WEBAUTHN_REGISTRATION_STARTED = 'passwordless:webauthn:registration:started',
  WEBAUTHN_REGISTRATION_COMPLETED = 'passwordless:webauthn:registration:completed',
  WEBAUTHN_REGISTRATION_FAILED = 'passwordless:webauthn:registration:failed',
  WEBAUTHN_AUTHENTICATION_STARTED = 'passwordless:webauthn:authentication:started',
  WEBAUTHN_AUTHENTICATION_COMPLETED = 'passwordless:webauthn:authentication:completed',
  WEBAUTHN_AUTHENTICATION_FAILED = 'passwordless:webauthn:authentication:failed',
  WEBAUTHN_CHALLENGE_GENERATED = 'passwordless:webauthn:challenge:generated',
  WEBAUTHN_CHALLENGE_VERIFIED = 'passwordless:webauthn:challenge:verified',

  // Magic link events
  MAGIC_LINK_SENT = 'passwordless:magic-link:sent',
  MAGIC_LINK_VERIFIED = 'passwordless:magic-link:verified',
  MAGIC_LINK_EXPIRED = 'passwordless:magic-link:expired',
  MAGIC_LINK_FAILED = 'passwordless:magic-link:failed',

  // Email OTP events
  OTP_SENT = 'passwordless:otp:sent',
  OTP_VERIFIED = 'passwordless:otp:verified',
  OTP_EXPIRED = 'passwordless:otp:expired',
  OTP_FAILED = 'passwordless:otp:failed',

  // Certificate events
  CERTIFICATE_REGISTRATION_STARTED = 'passwordless:certificate:registration:started',
  CERTIFICATE_REGISTRATION_COMPLETED = 'passwordless:certificate:registration:completed',
  CERTIFICATE_REGISTRATION_FAILED = 'passwordless:certificate:registration:failed',
  CERTIFICATE_AUTHENTICATION_STARTED = 'passwordless:certificate:authentication:started',
  CERTIFICATE_AUTHENTICATION_COMPLETED = 'passwordless:certificate:authentication:completed',
  CERTIFICATE_AUTHENTICATION_FAILED = 'passwordless:certificate:authentication:failed',

  // Biometric events
  BIOMETRIC_REGISTRATION_STARTED = 'passwordless:biometric:registration:started',
  BIOMETRIC_REGISTRATION_COMPLETED = 'passwordless:biometric:registration:completed',
  BIOMETRIC_REGISTRATION_FAILED = 'passwordless:biometric:registration:failed',
  BIOMETRIC_AUTHENTICATION_STARTED = 'passwordless:biometric:authentication:started',
  BIOMETRIC_AUTHENTICATION_COMPLETED = 'passwordless:biometric:authentication:completed',
  BIOMETRIC_AUTHENTICATION_FAILED = 'passwordless:biometric:authentication:failed',

  // General passwordless events
  AUTHENTICATION_STARTED = 'passwordless:authentication:started',
  AUTHENTICATION_SUCCEEDED = 'passwordless:authentication:succeeded',
  AUTHENTICATION_FAILED = 'passwordless:authentication:failed',
  REGISTRATION_STARTED = 'passwordless:registration:started',
  REGISTRATION_SUCCEEDED = 'passwordless:registration:succeeded',
  REGISTRATION_FAILED = 'passwordless:registration:failed',
  REGISTRATION_COMPLETED = 'passwordless:registration:completed',

  // Credential events
  CREDENTIAL_CREATED = 'passwordless:credential:created',
  CREDENTIAL_DELETED = 'passwordless:credential:deleted',
  CREDENTIAL_UPDATED = 'passwordless:credential:updated',
}
