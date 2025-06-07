import { z } from 'zod';

/**
 * User Validators
 * Comprehensive validation schemas for user profile operations
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

const phoneNumberSchema = z
  .string()
  .regex(/^\+[1-9]\d{1,14}$/, 'Phone number must be in E.164 format (e.g., +12125551234)')
  .optional();

const paginationSchema = z.object({
  page: z.coerce.number().int().positive().optional().default(1),
  limit: z.coerce.number().int().positive().max(100).optional().default(20),
});

/**
 * Context-aware validation
 */
export interface UserValidationContext {
  requestMetadata?: {
    ipAddress?: string;
    userAgent?: string;
  };
  securityLevel?: 'standard' | 'high';
  riskScore?: number;
}

/**
 * User validators
 */
export const userValidators = {
  /**
   * Update current user profile validator
   * Validates request to update user profile
   */
  updateCurrentUser: z.object({
    firstName: z.string().max(50, 'First name is too long').optional(),
    lastName: z.string().max(50, 'Last name is too long').optional(),
    displayName: z.string().max(100, 'Display name is too long').optional(),
    phoneNumber: phoneNumberSchema,
    preferences: z.record(z.any()).optional(),
  }),

  /**
   * Update user email validator
   * Validates request to update user email
   */
  updateEmail: z.object({
    email: emailSchema,
    password: z.string().min(1, 'Password is required'),
  }),

  /**
   * Update user phone number validator
   * Validates request to update user phone number
   */
  updatePhoneNumber: z.object({
    phoneNumber: z
      .string()
      .regex(/^\+[1-9]\d{1,14}$/, 'Phone number must be in E.164 format (e.g., +12125551234)'),
  }),

  /**
   * Verify phone number validator
   * Validates request to verify phone number with code
   */
  verifyPhoneNumber: z.object({
    code: z
      .string()
      .min(4, 'Verification code must be at least 4 characters')
      .max(10, 'Verification code is too long'),
  }),

  /**
   * Update user preferences validator
   * Validates request to update user preferences
   */
  updatePreferences: z.object({
    preferences: z.record(z.any()),
  }),

  /**
   * Get user activity log validator
   * Validates query parameters for retrieving user activity log
   */
  getActivityLog: z
    .object({
      ...paginationSchema.shape,
      startDate: z
        .string()
        .regex(
          /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$/,
          'Invalid date format. Use ISO 8601 format'
        )
        .optional(),
      endDate: z
        .string()
        .regex(
          /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$/,
          'Invalid date format. Use ISO 8601 format'
        )
        .optional(),
      activityType: z.string().optional(),
    })
    .refine(
      data => {
        // If both dates are provided, ensure startDate is before or equal to endDate
        if (data.startDate && data.endDate) {
          return new Date(data.startDate) <= new Date(data.endDate);
        }
        return true;
      },
      {
        message: 'Start date must be before or equal to end date',
        path: ['dateRange'],
      }
    ),

  /**
   * Request account deletion validator
   * Validates request to delete user account
   */
  requestAccountDeletion: z.object({
    password: z.string().min(1, 'Password is required'),
    reason: z.string().max(1000, 'Reason is too long').optional(),
    confirmPhrase: z.literal('DELETE MY ACCOUNT', {
      errorMap: () => ({ message: 'You must type DELETE MY ACCOUNT to confirm' }),
    }),
  }),

  /**
   * Cancel account deletion validator
   * Validates request to cancel account deletion
   */
  cancelAccountDeletion: z.object({
    // No additional fields required
  }),

  /**
   * Export user data validator
   * Validates request to export user data
   */
  exportUserData: z.object({
    format: z.enum(['json', 'csv', 'xml']).optional().default('json'),
    includeActivity: z.boolean().optional().default(true),
    includePreferences: z.boolean().optional().default(true),
  }),

  /**
   * Validation chain factory
   * Creates a validation chain with multiple validators
   */
  createValidationChain: <T extends z.ZodRawShape>(
    baseSchema: z.ZodObject<T>,
    options?: {
      securityLevel?: 'standard' | 'high';
      additionalChecks?: (data: any, context?: UserValidationContext) => boolean | Promise<boolean>;
      errorMessage?: string;
      errorCode?: string;
    }
  ) => {
    const { securityLevel = 'standard', additionalChecks, errorMessage, errorCode } = options || {};

    // Apply different validation rules based on security level
    let schema = baseSchema;

    if (securityLevel === 'high') {
      // For high security, we might enforce stricter rules
      // This is just an example - in a real implementation, you would add specific rules
      if (schema.shape && 'password' in schema.shape) {
        schema = schema as unknown as z.ZodObject<T>;
      }
    }

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
