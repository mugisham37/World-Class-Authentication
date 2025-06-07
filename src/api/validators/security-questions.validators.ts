import { z } from 'zod';

/**
 * Security Questions Validators
 * Comprehensive validation schemas for security questions operations
 */

/**
 * Common validation patterns
 */
const questionSchema = z
  .string()
  .min(5, 'Question must be at least 5 characters')
  .max(200, 'Question must be at most 200 characters');

const answerSchema = z
  .string()
  .min(2, 'Answer must be at least 2 characters')
  .max(100, 'Answer must be at most 100 characters')
  .transform(answer => answer.trim());

/**
 * Context-aware validation
 */
export interface SecurityQuestionsValidationContext {
  requestMetadata?: {
    ipAddress?: string;
    userAgent?: string;
  };
  securityLevel?: 'standard' | 'high';
  riskScore?: number;
}

/**
 * Security Questions validators
 */
export const securityQuestionsValidators = {
  /**
   * Setup security questions validator
   * Validates request to set up security questions
   */
  setupSecurityQuestions: z.object({
    questions: z
      .array(
        z.object({
          question: questionSchema,
          answer: answerSchema,
        })
      )
      .min(3, 'At least 3 security questions are required')
      .max(5, 'Maximum 5 security questions allowed'),
  }),

  /**
   * Update security questions validator
   * Validates request to update security questions
   */
  updateSecurityQuestions: z.object({
    questions: z
      .array(
        z.object({
          question: questionSchema,
          answer: answerSchema,
        })
      )
      .min(3, 'At least 3 security questions are required')
      .max(5, 'Maximum 5 security questions allowed'),
  }),

  /**
   * Verify security questions validator
   * Validates request to verify security questions during recovery
   */
  verifySecurityQuestions: z.object({
    requestId: z.string().uuid('Invalid request ID format'),
    answers: z
      .array(
        z.object({
          questionId: z.string().min(1, 'Question ID is required'),
          answer: answerSchema,
        })
      )
      .min(1, 'At least one answer is required'),
  }),

  /**
   * Get security questions validator
   * Validates request to retrieve user's security questions
   */
  getUserQuestions: z.object({
    includeAnswers: z.boolean().optional().default(false),
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
        context?: SecurityQuestionsValidationContext
      ) => boolean | Promise<boolean>;
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
      if (schema.shape && 'questions' in schema.shape) {
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
