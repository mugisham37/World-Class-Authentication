import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define MFA config schema with Zod
const mfaConfigSchema = z.object({
  totp: z.object({
    issuer: z.string().default('Auth System'),
    window: z.number().int().positive().default(1), // Number of windows to check
    stepSeconds: z.number().int().positive().default(30), // TOTP step in seconds
    digits: z.number().int().min(6).max(8).default(6), // Number of digits in TOTP code
    algorithm: z.enum(['sha1', 'sha256', 'sha512']).default('sha1'),
    secretLength: z.number().int().min(16).max(64).default(20), // Length of TOTP secret
  }),
  webauthn: z.object({
    rpName: z.string().default('Auth System'),
    rpID: z.string().optional(), // Defaults to the domain name
    origin: z.string().optional(), // Defaults to the origin
    challengeSize: z.number().int().min(32).max(128).default(64),
    timeout: z.number().int().positive().default(60000), // 60 seconds
    attestation: z.enum(['none', 'indirect', 'direct']).default('none'),
    userVerification: z.enum(['required', 'preferred', 'discouraged']).default('preferred'),
  }),
  sms: z.object({
    provider: z.enum(['twilio', 'aws-sns', 'mock']).default('mock'),
    codeLength: z.number().int().min(4).max(10).default(6),
    expiration: z
      .number()
      .int()
      .positive()
      .default(10 * 60), // 10 minutes
    rateLimit: z.object({
      maxAttempts: z.number().int().positive().default(3),
      windowMs: z
        .number()
        .int()
        .positive()
        .default(10 * 60 * 1000), // 10 minutes
    }),
  }),
  email: z.object({
    codeLength: z.number().int().min(6).max(12).default(8),
    expiration: z
      .number()
      .int()
      .positive()
      .default(15 * 60), // 15 minutes
    rateLimit: z.object({
      maxAttempts: z.number().int().positive().default(3),
      windowMs: z
        .number()
        .int()
        .positive()
        .default(15 * 60 * 1000), // 15 minutes
    }),
  }),
  recoveryCodes: z.object({
    count: z.number().int().min(5).max(20).default(10),
    length: z.number().int().min(8).max(24).default(12),
    format: z.enum(['alphanumeric', 'numeric', 'hex']).default('alphanumeric'),
    separator: z.string().max(1).default('-'),
    groupSize: z.number().int().min(3).max(6).default(4),
  }),
  pushNotification: z.object({
    provider: z.enum(['firebase', 'apns', 'mock']).default('mock'),
    expiration: z
      .number()
      .int()
      .positive()
      .default(2 * 60), // 2 minutes
    rateLimit: z.object({
      maxAttempts: z.number().int().positive().default(3),
      windowMs: z
        .number()
        .int()
        .positive()
        .default(5 * 60 * 1000), // 5 minutes
    }),
  }),
  general: z.object({
    maxActiveMethods: z.number().int().positive().default(5),
    maxFailedAttempts: z.number().int().positive().default(5),
    lockoutDuration: z
      .number()
      .int()
      .positive()
      .default(30 * 60), // 30 minutes
    rememberDeviceDuration: z
      .number()
      .int()
      .positive()
      .default(30 * 24 * 60 * 60), // 30 days
    challengeExpiration: z
      .number()
      .int()
      .positive()
      .default(5 * 60), // 5 minutes
    adaptiveMfaEnabled: z.boolean().default(true),
  }),
});

// Parse and validate environment variables
const rawConfig = {
  totp: {
    issuer: env.get('MFA_TOTP_ISSUER'),
    window: env.getNumber('MFA_TOTP_WINDOW'),
    stepSeconds: env.getNumber('MFA_TOTP_STEP_SECONDS'),
    digits: env.getNumber('MFA_TOTP_DIGITS'),
    algorithm: env.get('MFA_TOTP_ALGORITHM') as 'sha1' | 'sha256' | 'sha512',
    secretLength: env.getNumber('MFA_TOTP_SECRET_LENGTH'),
  },
  webauthn: {
    rpName: env.get('MFA_WEBAUTHN_RP_NAME'),
    rpID: env.get('MFA_WEBAUTHN_RP_ID'),
    origin: env.get('MFA_WEBAUTHN_ORIGIN'),
    challengeSize: env.getNumber('MFA_WEBAUTHN_CHALLENGE_SIZE'),
    timeout: env.getNumber('MFA_WEBAUTHN_TIMEOUT'),
    attestation: env.get('MFA_WEBAUTHN_ATTESTATION') as 'none' | 'indirect' | 'direct',
    userVerification: env.get('MFA_WEBAUTHN_USER_VERIFICATION') as
      | 'required'
      | 'preferred'
      | 'discouraged',
  },
  sms: {
    provider: env.get('MFA_SMS_PROVIDER') as 'twilio' | 'aws-sns' | 'mock',
    codeLength: env.getNumber('MFA_SMS_CODE_LENGTH'),
    expiration: env.getNumber('MFA_SMS_EXPIRATION'),
    rateLimit: {
      maxAttempts: env.getNumber('MFA_SMS_RATE_LIMIT_MAX_ATTEMPTS'),
      windowMs: env.getNumber('MFA_SMS_RATE_LIMIT_WINDOW_MS'),
    },
  },
  email: {
    codeLength: env.getNumber('MFA_EMAIL_CODE_LENGTH'),
    expiration: env.getNumber('MFA_EMAIL_EXPIRATION'),
    rateLimit: {
      maxAttempts: env.getNumber('MFA_EMAIL_RATE_LIMIT_MAX_ATTEMPTS'),
      windowMs: env.getNumber('MFA_EMAIL_RATE_LIMIT_WINDOW_MS'),
    },
  },
  recoveryCodes: {
    count: env.getNumber('MFA_RECOVERY_CODES_COUNT'),
    length: env.getNumber('MFA_RECOVERY_CODES_LENGTH'),
    format: env.get('MFA_RECOVERY_CODES_FORMAT') as 'alphanumeric' | 'numeric' | 'hex',
    separator: env.get('MFA_RECOVERY_CODES_SEPARATOR'),
    groupSize: env.getNumber('MFA_RECOVERY_CODES_GROUP_SIZE'),
  },
  pushNotification: {
    provider: env.get('MFA_PUSH_NOTIFICATION_PROVIDER') as 'firebase' | 'apns' | 'mock',
    expiration: env.getNumber('MFA_PUSH_NOTIFICATION_EXPIRATION'),
    rateLimit: {
      maxAttempts: env.getNumber('MFA_PUSH_NOTIFICATION_RATE_LIMIT_MAX_ATTEMPTS'),
      windowMs: env.getNumber('MFA_PUSH_NOTIFICATION_RATE_LIMIT_WINDOW_MS'),
    },
  },
  general: {
    maxActiveMethods: env.getNumber('MFA_MAX_ACTIVE_METHODS'),
    maxFailedAttempts: env.getNumber('MFA_MAX_FAILED_ATTEMPTS'),
    lockoutDuration: env.getNumber('MFA_LOCKOUT_DURATION'),
    rememberDeviceDuration: env.getNumber('MFA_REMEMBER_DEVICE_DURATION'),
    challengeExpiration: env.getNumber('MFA_CHALLENGE_EXPIRATION'),
    adaptiveMfaEnabled: env.getBoolean('MFA_ADAPTIVE_ENABLED'),
  },
};

// Validate and export config
export const mfaConfig = validateConfig(mfaConfigSchema, rawConfig);

// Export config type
export type MfaConfig = typeof mfaConfig;
