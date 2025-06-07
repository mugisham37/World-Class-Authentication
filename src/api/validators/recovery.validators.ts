import { z } from 'zod';
import { RecoveryMethodType } from '../../core/recovery/recovery-method';

/**
 * Recovery Validators
 * Comprehensive validation schemas for account recovery operations
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

const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters')
  .max(100, 'Password is too long')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number')
  .regex(/[^a-zA-Z0-9]/, 'Password must contain at least one special character');

const methodNameSchema = z
  .string()
  .min(1, 'Method name is required')
  .max(100, 'Method name is too long')
  .transform(name => name.trim());

const requestIdSchema = z.string().uuid('Invalid request ID format');

/**
 * Context-aware validation
 */
export interface RecoveryValidationContext {
  requestMetadata?: {
    ipAddress?: string;
    userAgent?: string;
    deviceId?: string;
    location?: string;
  };
  securityLevel?: 'standard' | 'high' | 'paranoid';
  riskScore?: number;
  complianceRequirements?: {
    requiresIdentityVerification: boolean;
    requiresMultipleFactors: boolean;
    requiresAdminApproval: boolean;
  };
}

/**
 * Recovery validators
 */
export const recoveryValidators = {
  /**
   * Validator for registering a recovery method
   */
  registerRecoveryMethod: z.object({
    type: z.nativeEnum(RecoveryMethodType, {
      errorMap: () => ({ message: 'Invalid recovery method type' }),
    }),
    name: methodNameSchema,
    data: z.record(z.any()).optional(),
  }),

  /**
   * Validator for initiating account recovery
   */
  initiateRecovery: z.object({
    email: emailSchema,
    methodType: z.nativeEnum(RecoveryMethodType, {
      errorMap: () => ({ message: 'Invalid recovery method type' }),
    }),
  }),

  /**
   * Validator for verifying recovery challenge
   */
  verifyRecoveryChallenge: z.object({
    requestId: requestIdSchema,
    verificationData: z.record(z.any()),
  }),

  /**
   * Validator for completing account recovery
   */
  completeRecovery: z
    .object({
      token: z.string().min(1, 'Recovery token is required'),
      newPassword: passwordSchema,
      confirmPassword: z.string().min(1, 'Confirm password is required'),
    })
    .refine(data => data.newPassword === data.confirmPassword, {
      message: 'Passwords do not match',
      path: ['confirmPassword'],
    }),

  /**
   * Validator for setting security questions
   */
  setSecurityQuestions: z.object({
    questions: z
      .array(
        z.object({
          question: z.string().min(1, 'Question is required'),
          answer: z.string().min(3, 'Answer must be at least 3 characters'),
        })
      )
      .min(3, 'At least 3 security questions are required')
      .max(5, 'Maximum 5 security questions allowed'),
  }),

  /**
   * Validator for verifying security questions
   */
  verifySecurityQuestions: z.object({
    requestId: requestIdSchema,
    answers: z
      .array(
        z.object({
          questionId: z.string().min(1, 'Question ID is required'),
          answer: z.string().min(1, 'Answer is required'),
        })
      )
      .min(1, 'At least one answer is required'),
  }),

  /**
   * Validator for adding a trusted contact
   */
  addTrustedContact: z.object({
    name: z.string().min(1, 'Contact name is required'),
    email: emailSchema,
    phone: z.string().optional(),
    relationship: z.string().optional(),
  }),

  /**
   * Validator for trusted contact recovery verification
   */
  verifyTrustedContactRecovery: z.object({
    requestId: requestIdSchema,
    code: z.string().min(6, 'Recovery code must be at least 6 characters'),
  }),

  /**
   * Validator for email recovery verification
   */
  verifyEmailRecovery: z.object({
    requestId: requestIdSchema,
    code: z.string().min(6, 'Verification code must be at least 6 characters'),
  }),

  /**
   * Validator for SMS recovery verification
   */
  verifySmsRecovery: z.object({
    requestId: requestIdSchema,
    code: z.string().min(4, 'Verification code must be at least 4 characters'),
  }),

  /**
   * Validator for canceling a recovery request
   */
  cancelRecoveryRequest: z.object({
    requestId: requestIdSchema,
  }),

  /**
   * Validator for identity verification during recovery
   */
  verifyIdentity: z.object({
    requestId: requestIdSchema,
    documentType: z.enum(['passport', 'drivers_license', 'national_id', 'other']),
    documentNumber: z.string().min(1, 'Document number is required'),
    documentImage: z.string().optional(), // Base64 encoded image or file reference
    selfieImage: z.string().optional(), // Base64 encoded image or file reference
    additionalInfo: z.record(z.any()).optional(),
  }),

  /**
   * Validator for admin approval of recovery
   */
  adminApproveRecovery: z.object({
    requestId: requestIdSchema,
    adminId: z.string().uuid('Invalid admin ID'),
    notes: z.string().optional(),
  }),

  /**
   * Validator for updating recovery method
   */
  updateRecoveryMethod: z.object({
    methodId: z.string().uuid('Invalid method ID'),
    name: methodNameSchema.optional(),
    data: z.record(z.any()).optional(),
    isEnabled: z.boolean().optional(),
  }),

  /**
   * Validator for recovery flow state management
   */
  updateRecoveryFlowState: z.object({
    requestId: requestIdSchema,
    state: z.enum([
      'initiated',
      'verification_pending',
      'verification_completed',
      'identity_verification_pending',
      'admin_approval_pending',
      'approved',
      'completed',
      'cancelled',
      'expired',
      'failed',
    ]),
    metadata: z.record(z.any()).optional(),
  }),

  /**
   * Validator for recovery method priority
   */
  updateRecoveryMethodPriority: z
    .object({
      methodIds: z.array(z.string().uuid('Invalid method ID')),
    })
    .refine(data => new Set(data.methodIds).size === data.methodIds.length, {
      message: 'Duplicate method IDs are not allowed',
      path: ['methodIds'],
    }),

  /**
   * Validator for recovery settings
   */
  updateRecoverySettings: z.object({
    allowedMethods: z.array(z.nativeEnum(RecoveryMethodType)).optional(),
    requireMultipleFactors: z.boolean().optional(),
    requireIdentityVerification: z.boolean().optional(),
    requireAdminApproval: z.boolean().optional(),
    recoveryTokenExpirationHours: z.number().int().min(1).max(72).optional(),
    cooldownPeriodMinutes: z.number().int().min(0).max(1440).optional(),
    maxAttemptsBeforeLockout: z.number().int().min(1).max(10).optional(),
  }),

  /**
   * Fraud detection for recovery attempts
   */
  validateRecoveryAttempt: (): { isValid: boolean; riskScore: number; reason?: string } => {
    // This is a placeholder for actual fraud detection logic
    // In a real implementation, this would check for suspicious patterns
    const riskScore = Math.random() * 100;
    return {
      isValid: riskScore < 75,
      riskScore,
      reason: riskScore >= 75 ? 'Suspicious recovery attempt detected' : undefined,
    };
  },

  /**
   * Validator for recovery method verification
   */
  verifyRecoveryMethod: z.object({
    methodId: z.string().uuid('Invalid method ID'),
    verificationData: z.record(z.any()),
  }),

  /**
   * Validator for backup code verification
   */
  verifyBackupCode: z.object({
    code: z.string().min(8, 'Backup code must be at least 8 characters'),
    userId: z.string().uuid('Invalid user ID'),
  }),

  /**
   * Validator for generating new backup codes
   */
  generateBackupCodes: z.object({
    count: z.number().int().min(5).max(20).default(10),
    password: z.string().min(1, 'Password is required for security verification'),
  }),
};
