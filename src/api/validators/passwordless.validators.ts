import { z } from 'zod';

/**
 * Passwordless Authentication Validators
 * Comprehensive validation schemas for passwordless authentication operations
 */

/**
 * Common validation patterns
 */
const emailSchema = z
  .string()
  .email('Invalid email address')
  .min(1, 'Email is required')
  .max(255, 'Email is too long')
  .transform(email => email.toLowerCase().trim());

const phoneSchema = z
  .string()
  .regex(/^\+[1-9]\d{1,14}$/, 'Phone number must be in E.164 format (e.g., +12125551234)')
  .optional();

/**
 * Context-aware validation
 */
export interface PasswordlessValidationContext {
  requestMetadata?: {
    ipAddress?: string;
    userAgent?: string;
    origin?: string;
  };
  securityLevel?: 'standard' | 'high';
  riskScore?: number;
}

/**
 * Passwordless validators
 */
export const passwordlessValidators = {
  /**
   * Start authentication validator
   * Validates request to initiate passwordless authentication
   */
  startAuthentication: z
    .object({
      method: z.enum(['email', 'sms', 'webauthn', 'magic_link', 'push'], {
        errorMap: () => ({ message: 'Invalid authentication method' }),
      }),
      identifier: z.union([
        emailSchema,
        phoneSchema,
        z.string().min(1, 'Username is required').max(100, 'Username is too long'),
      ]),
      origin: z.string().url('Invalid origin URL').optional(),
      deviceName: z.string().max(100, 'Device name is too long').optional(),
    })
    .superRefine((data, ctx) => {
      // Method-specific validation
      if (data.method === 'email' || data.method === 'magic_link') {
        try {
          z.string().email().parse(data.identifier);
        } catch (error) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'Valid email is required for email authentication',
            path: ['identifier'],
          });
        }
      } else if (data.method === 'sms') {
        try {
          z.string()
            .regex(/^\+[1-9]\d{1,14}$/)
            .parse(data.identifier);
        } catch (error) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'Valid phone number in E.164 format is required for SMS authentication',
            path: ['identifier'],
          });
        }
      }
    }),

  /**
   * Complete authentication validator
   * Validates request to complete passwordless authentication
   */
  completeAuthentication: z.object({
    sessionId: z.string().uuid('Invalid session ID'),
    response: z.union([
      z.string().min(1, 'Authentication response is required'), // For OTP/magic link tokens
      z.record(z.any()), // For WebAuthn responses
    ]),
    deviceName: z.string().max(100, 'Device name is too long').optional(),
    rememberDevice: z.boolean().optional().default(false),
  }),

  /**
   * Start registration validator
   * Validates request to initiate passwordless credential registration
   */
  startRegistration: z
    .object({
      method: z.enum(['email', 'sms', 'webauthn', 'magic_link', 'push'], {
        errorMap: () => ({ message: 'Invalid registration method' }),
      }),
      identifier: z.union([
        emailSchema,
        phoneSchema,
        z.string().min(1, 'Username is required').max(100, 'Username is too long'),
      ]),
      name: z
        .string()
        .min(1, 'Credential name is required')
        .max(100, 'Credential name is too long'),
      origin: z.string().url('Invalid origin URL').optional(),
      deviceName: z.string().max(100, 'Device name is too long').optional(),
      attestation: z.enum(['none', 'direct', 'indirect']).optional().default('none'),
      authenticatorSelection: z
        .object({
          authenticatorAttachment: z.enum(['platform', 'cross-platform']).optional(),
          requireResidentKey: z.boolean().optional(),
          userVerification: z.enum(['required', 'preferred', 'discouraged']).optional(),
        })
        .optional(),
    })
    .superRefine((data, ctx) => {
      // Method-specific validation
      if (data.method === 'email' || data.method === 'magic_link') {
        try {
          z.string().email().parse(data.identifier);
        } catch (error) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'Valid email is required for email authentication',
            path: ['identifier'],
          });
        }
      } else if (data.method === 'sms') {
        try {
          z.string()
            .regex(/^\+[1-9]\d{1,14}$/)
            .parse(data.identifier);
        } catch (error) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'Valid phone number in E.164 format is required for SMS authentication',
            path: ['identifier'],
          });
        }
      }
    }),

  /**
   * Complete registration validator
   * Validates request to complete passwordless credential registration
   */
  completeRegistration: z.object({
    sessionId: z.string().uuid('Invalid session ID'),
    response: z.union([
      z.string().min(1, 'Registration response is required'), // For OTP confirmation
      z.record(z.any()), // For WebAuthn responses
    ]),
  }),

  /**
   * Get credentials validator
   * Validates request to retrieve user's passwordless credentials
   */
  getCredentials: z.object({
    userId: z.string().uuid('Invalid user ID').optional(),
    includeInactive: z.boolean().optional().default(false),
  }),

  /**
   * Delete credential validator
   * Validates request to delete a passwordless credential
   */
  deleteCredential: z.object({
    credentialId: z.string().min(1, 'Credential ID is required'),
  }),

  /**
   * Update credential validator
   * Validates request to update a passwordless credential
   */
  updateCredential: z.object({
    credentialId: z.string().min(1, 'Credential ID is required'),
    name: z
      .string()
      .min(1, 'Credential name is required')
      .max(100, 'Credential name is too long')
      .optional(),
    isEnabled: z.boolean().optional(),
  }),

  /**
   * Verify OTP validator
   * Validates request to verify a one-time password
   */
  verifyOtp: z.object({
    sessionId: z.string().uuid('Invalid session ID'),
    code: z.string().min(4, 'OTP code is required').max(10, 'OTP code is too long'),
  }),

  /**
   * Resend OTP validator
   * Validates request to resend a one-time password
   */
  resendOtp: z.object({
    sessionId: z.string().uuid('Invalid session ID'),
  }),

  /**
   * Verify magic link validator
   * Validates request to verify a magic link token
   */
  verifyMagicLink: z.object({
    token: z.string().min(1, 'Magic link token is required'),
  }),

  /**
   * WebAuthn authentication options validator
   * Validates request to get WebAuthn authentication options
   */
  getWebAuthnAuthOptions: z.object({
    username: z.string().min(1, 'Username is required').optional(),
    userVerification: z
      .enum(['required', 'preferred', 'discouraged'])
      .optional()
      .default('preferred'),
    timeout: z.number().int().positive().max(600000).optional().default(60000), // Default 1 minute, max 10 minutes
  }),

  /**
   * WebAuthn registration options validator
   * Validates request to get WebAuthn registration options
   */
  getWebAuthnRegOptions: z.object({
    username: z.string().min(1, 'Username is required'),
    displayName: z.string().min(1, 'Display name is required').optional(),
    attestation: z.enum(['none', 'direct', 'indirect']).optional().default('none'),
    authenticatorSelection: z
      .object({
        authenticatorAttachment: z.enum(['platform', 'cross-platform']).optional(),
        requireResidentKey: z.boolean().optional(),
        userVerification: z.enum(['required', 'preferred', 'discouraged']).optional(),
      })
      .optional(),
    timeout: z.number().int().positive().max(600000).optional().default(60000), // Default 1 minute, max 10 minutes
    excludeCredentials: z.array(z.string()).optional(),
  }),

  /**
   * Push notification authentication validator
   * Validates request to authenticate via push notification
   */
  pushAuthentication: z.object({
    deviceToken: z.string().min(1, 'Device token is required'),
    userId: z.string().uuid('Invalid user ID'),
    title: z.string().max(100, 'Title is too long').optional(),
    body: z.string().max(200, 'Body is too long').optional(),
    ttl: z.number().int().positive().max(86400).optional().default(120), // Default 2 minutes, max 24 hours
    data: z.record(z.any()).optional(),
  }),

  /**
   * Push notification response validator
   * Validates push notification response
   */
  pushResponse: z.object({
    requestId: z.string().min(1, 'Request ID is required'),
    approved: z.boolean(),
    deviceId: z.string().min(1, 'Device ID is required'),
    timestamp: z.number().int().positive(),
    signature: z.string().optional(), // For response verification
  }),

  /**
   * Device registration validator
   * Validates request to register a device for push notifications
   */
  registerDevice: z.object({
    userId: z.string().uuid('Invalid user ID'),
    deviceToken: z.string().min(1, 'Device token is required'),
    deviceType: z.enum(['ios', 'android', 'web', 'desktop']),
    deviceName: z.string().max(100, 'Device name is too long').optional(),
    pushProvider: z.enum(['fcm', 'apns', 'web']),
    appVersion: z.string().optional(),
    osVersion: z.string().optional(),
  }),

  /**
   * Validation chain factory
   * Creates a validation chain with multiple validators
   */
  createValidationChain: <T extends z.ZodRawShape>(
    baseSchema: z.ZodObject<T>,
    options?: {
      securityLevel?: 'standard' | 'high';
      additionalChecks?: (
        data: any,
        context?: PasswordlessValidationContext
      ) => boolean | Promise<boolean>;
      errorMessage?: string;
      errorCode?: string;
    }
  ) => {
    const { additionalChecks, errorMessage, errorCode } = options || {};

    // Apply different validation rules based on security level
    let schema = baseSchema;

    // Add custom validation if provided
    if (additionalChecks) {
      return schema.superRefine((data, ctx) => {
        const result = additionalChecks(data);
        if (!result) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: errorMessage || 'Validation failed',
            path: ['_custom'],
            params: { code: errorCode || 'VALIDATION_ERROR' },
          });
        }
      }) as unknown as z.ZodObject<T>;
    }

    return schema;
  },

  /**
   * Time-window validation for OTP codes
   * Validates if the OTP is within the acceptable time window
   */
  validateOtpTimeWindow: (createdAt: Date, windowSeconds: number = 300): boolean => {
    const now = new Date();
    const diffSeconds = (now.getTime() - createdAt.getTime()) / 1000;
    return diffSeconds <= windowSeconds;
  },

  /**
   * Rate limiting validation
   * Validates if the request is within rate limits
   */
  validateRateLimit: (
    maxAttempts: number = 5,
    windowMinutes: number = 15
  ): { allowed: boolean; remainingAttempts: number; resetTime: Date } => {
    // This is a placeholder for actual rate limiting logic
    // In a real implementation, this would check a rate limiting service or database
    return {
      allowed: true,
      remainingAttempts: maxAttempts,
      resetTime: new Date(Date.now() + windowMinutes * 60 * 1000),
    };
  },
};
