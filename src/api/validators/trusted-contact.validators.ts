import { z } from 'zod';

/**
 * Trusted Contact Validators
 * Comprehensive validation schemas for trusted contact operations
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

const nameSchema = z
  .string()
  .min(1, 'Name is required')
  .max(100, 'Name is too long')
  .transform(name => name.trim());

const relationshipSchema = z.string().max(50, 'Relationship is too long').optional();

/**
 * Context-aware validation
 */
export interface TrustedContactValidationContext {
  requestMetadata?: {
    ipAddress?: string;
    userAgent?: string;
  };
  securityLevel?: 'standard' | 'high';
  riskScore?: number;
}

/**
 * Trusted Contact validators
 */
export const trustedContactValidators = {
  /**
   * Add trusted contact validator
   * Validates request to add a trusted contact
   */
  addTrustedContact: z.object({
    name: nameSchema,
    email: emailSchema,
    relationship: relationshipSchema,
  }),

  /**
   * Remove trusted contact validator
   * Validates request to remove a trusted contact
   */
  removeTrustedContact: z.object({
    contactId: z.string().min(1, 'Contact ID is required'),
  }),

  /**
   * Register recovery method validator
   * Validates request to register trusted contacts as a recovery method
   */
  registerRecoveryMethod: z.object({
    name: z
      .string()
      .min(1, 'Method name is required')
      .max(100, 'Method name is too long')
      .optional(),
    contacts: z
      .array(
        z.object({
          id: z.string().min(1, 'Contact ID is required'),
        })
      )
      .min(1, 'At least one contact is required'),
  }),

  /**
   * Initiate recovery validator
   * Validates request to initiate recovery using trusted contacts
   */
  initiateRecovery: z.object({
    userId: z.string().uuid('Invalid user ID format'),
    requestId: z.string().uuid('Invalid request ID format'),
  }),

  /**
   * Verify recovery validator
   * Validates request to verify recovery code from trusted contacts
   */
  verifyRecovery: z.object({
    requestId: z.string().uuid('Invalid request ID format'),
    code: z
      .string()
      .min(6, 'Recovery code must be at least 6 characters')
      .max(50, 'Recovery code is too long'),
  }),

  /**
   * Check availability validator
   * Validates request to check if trusted contact recovery is available for a user
   */
  checkAvailability: z.object({
    userId: z.string().uuid('Invalid user ID format'),
  }),

  /**
   * Get user contacts validator
   * Validates request to retrieve user's trusted contacts
   */
  getUserContacts: z.object({
    includeInactive: z.boolean().optional().default(false),
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
        context?: TrustedContactValidationContext
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
};
