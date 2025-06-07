import { z } from 'zod';
import { MfaFactorType } from '../../core/mfa/mfa-factor-types';

/**
 * MFA Validators
 * Comprehensive validation schemas for multi-factor authentication operations
 */

/**
 * Common validation patterns
 */
const factorNameSchema = z
  .string()
  .min(1, 'Factor name is required')
  .max(100, 'Factor name is too long')
  .trim();

const factorIdSchema = z.string().uuid('Invalid factor ID format');

const challengeIdSchema = z.string().uuid('Invalid challenge ID format');

/**
 * Context-aware validation
 */
export interface MfaValidationContext {
  requestMetadata?: {
    ipAddress?: string;
    userAgent?: string;
    deviceId?: string;
    origin?: string;
  };
  securityLevel?: 'standard' | 'high' | 'paranoid';
  riskScore?: number;
}

/**
 * MFA validators
 */
export const mfaValidators = {
  /**
   * Validator for starting MFA factor enrollment
   */
  startFactorEnrollment: z.object({
    factorType: z.nativeEnum(MfaFactorType, {
      errorMap: () => ({ message: 'Invalid MFA factor type' }),
    }),
    factorName: factorNameSchema,
    factorData: z
      .object({
        // Common optional fields for different factor types
        phoneNumber: z
          .string()
          .regex(
            /^\+?[1-9]\d{1,14}$/,
            'Invalid phone number format. Use E.164 format (e.g., +12125551234)'
          )
          .optional(),
        email: z.string().email('Invalid email format').optional(),
        deviceToken: z.string().optional(),
        // WebAuthn specific fields
        authenticatorAttachment: z.enum(['platform', 'cross-platform']).optional(),
        userVerification: z.enum(['required', 'preferred', 'discouraged']).optional(),
        // Additional fields can be added as needed
      })
      .optional(),
  }),

  /**
   * Validator for verifying MFA factor enrollment
   */
  verifyFactorEnrollment: z
    .object({
      factorId: factorIdSchema,
      // Different verification methods based on factor type
      code: z.string().optional(),
      attestationResponse: z.any().optional(), // For WebAuthn
      // Add other verification data fields as needed
    })
    .refine(data => data.code !== undefined || data.attestationResponse !== undefined, {
      message: 'Verification data is required',
      path: ['_verification'],
    }),

  /**
   * Validator for generating MFA challenge
   */
  generateChallenge: z.object({
    factorId: factorIdSchema,
    metadata: z.record(z.any()).optional(),
  }),

  /**
   * Validator for verifying MFA challenge
   */
  verifyChallenge: z.object({
    challengeId: challengeIdSchema,
    response: z.string().min(1, 'Response is required'),
    metadata: z.record(z.any()).optional(),
  }),

  /**
   * Validator for enabling/disabling MFA factor
   */
  updateFactorStatus: z.object({
    factorId: factorIdSchema,
  }),

  /**
   * Validator for deleting MFA factor
   */
  deleteFactor: z.object({
    factorId: factorIdSchema,
    // Optional confirmation for enhanced security
    confirmation: z.boolean().optional(),
  }),

  /**
   * Validator for regenerating recovery codes
   */
  regenerateRecoveryCodes: z.object({
    // Optional password confirmation for enhanced security
    password: z.string().optional(),
  }),

  /**
   * Validator for verifying recovery code
   */
  verifyRecoveryCode: z.object({
    recoveryCode: z.string().min(1, 'Recovery code is required'),
    userId: z.string().uuid('Invalid user ID'),
  }),

  /**
   * Validator for MFA setup completion
   */
  completeMfaSetup: z.object({
    setupToken: z.string().min(1, 'Setup token is required'),
    factorIds: z
      .array(z.string().uuid('Invalid factor ID'))
      .min(1, 'At least one factor is required'),
  }),

  /**
   * Validator for MFA authentication during login
   */
  authenticateWithMfa: z
    .object({
      sessionToken: z.string().min(1, 'Session token is required'),
      factorId: factorIdSchema,
      code: z.string().optional(),
      assertionResponse: z.any().optional(), // For WebAuthn
    })
    .refine(data => data.code !== undefined || data.assertionResponse !== undefined, {
      message: 'Authentication data is required',
      path: ['_authentication'],
    }),

  /**
   * Validator for TOTP-specific factor enrollment
   */
  totpFactorEnrollment: z.object({
    factorName: factorNameSchema,
    code: z
      .string()
      .min(6, 'TOTP code must be at least 6 digits')
      .max(8, 'TOTP code must be at most 8 digits'),
  }),

  /**
   * Validator for SMS-specific factor enrollment
   */
  smsFactorEnrollment: z.object({
    factorName: factorNameSchema,
    phoneNumber: z
      .string()
      .regex(
        /^\+?[1-9]\d{1,14}$/,
        'Invalid phone number format. Use E.164 format (e.g., +12125551234)'
      ),
    code: z
      .string()
      .min(4, 'SMS code must be at least 4 digits')
      .max(8, 'SMS code must be at most 8 digits'),
  }),

  /**
   * Validator for Email-specific factor enrollment
   */
  emailFactorEnrollment: z.object({
    factorName: factorNameSchema,
    email: z.string().email('Invalid email format'),
    code: z
      .string()
      .min(6, 'Email code must be at least 6 characters')
      .max(8, 'Email code must be at most 8 characters'),
  }),

  /**
   * Validator for WebAuthn-specific factor enrollment
   */
  webauthnFactorEnrollment: z.object({
    factorName: factorNameSchema,
    attestationResponse: z.any(),
  }),

  /**
   * Validator for Push Notification-specific factor enrollment
   */
  pushFactorEnrollment: z.object({
    factorName: factorNameSchema,
    deviceToken: z.string().min(1, 'Device token is required'),
    deviceType: z.enum(['ios', 'android', 'web']),
    deviceName: z.string().min(1, 'Device name is required'),
  }),

  /**
   * Validator for MFA enforcement settings
   */
  updateMfaEnforcement: z.object({
    enforced: z.boolean(),
    gracePeriodsInDays: z.number().int().min(0).optional(),
    allowedFactorTypes: z.array(z.nativeEnum(MfaFactorType)).optional(),
    exemptUserIds: z.array(z.string().uuid('Invalid user ID')).optional(),
    exemptRoles: z.array(z.string()).optional(),
  }),

  /**
   * Validator for MFA factor verification window
   */
  updateVerificationWindow: z.object({
    factorType: z.nativeEnum(MfaFactorType),
    windowInSeconds: z.number().int().min(30).max(300),
  }),

  /**
   * Validator for MFA challenge expiration
   */
  updateChallengeExpiration: z.object({
    factorType: z.nativeEnum(MfaFactorType),
    expirationInSeconds: z.number().int().min(60).max(900),
  }),

  /**
   * Validator for MFA rate limiting
   */
  updateRateLimiting: z.object({
    maxAttempts: z.number().int().min(3).max(10),
    windowInSeconds: z.number().int().min(60).max(3600),
    blockDurationInSeconds: z.number().int().min(300).max(86400),
  }),

  /**
   * Time window validation for TOTP
   */
  validateTimeWindow: (code: string, timestamp: number, windowSize: number = 30): boolean => {
    // This is a placeholder for actual TOTP validation logic
    // In a real implementation, this would validate the TOTP code against the current time
    return code.length >= 6 && timestamp > 0 && windowSize >= 30;
  },

  /**
   * Entropy analysis for generated codes
   */
  validateCodeEntropy: (code: string, minEntropy: number = 30): boolean => {
    // This is a placeholder for actual entropy validation logic
    // In a real implementation, this would calculate the entropy of the code
    return code.length >= 6 && minEntropy >= 30;
  },
};
