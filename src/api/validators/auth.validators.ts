import { z } from 'zod';

/**
 * Authentication Validators
 * Comprehensive validation schemas for authentication operations
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

const usernameSchema = z
  .string()
  .min(3, 'Username must be at least 3 characters')
  .max(30, 'Username must be at most 30 characters')
  .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores')
  .transform(username => username.trim());

/**
 * Context-aware validation
 */
export interface AuthValidationContext {
  requestMetadata?: {
    ipAddress?: string;
    userAgent?: string;
    deviceId?: string;
  };
  securityLevel?: 'standard' | 'high';
  riskScore?: number;
  complianceRequirements?: {
    requireStrongPassword?: boolean;
    requireMfa?: boolean;
    passwordHistoryCheck?: boolean;
    maxLoginAttempts?: number;
  };
}

/**
 * Authentication validators
 */
export const authValidators = {
  /**
   * Register validator
   * Validates user registration data
   */
  register: z.object({
    email: emailSchema,
    password: passwordSchema,
    username: usernameSchema,
    firstName: z.string().max(50, 'First name is too long').optional(),
    lastName: z.string().max(50, 'Last name is too long').optional(),
    phoneNumber: z
      .string()
      .regex(/^\+[1-9]\d{1,14}$/, 'Phone number must be in E.164 format (e.g., +12125551234)')
      .optional(),
    acceptTerms: z.boolean().refine(val => val === true, {
      message: 'You must accept the terms and conditions',
    }),
    captchaToken: z.string().optional(),
  }),

  /**
   * Login validator
   * Validates user login credentials
   */
  login: z.object({
    email: emailSchema,
    password: z.string().min(1, 'Password is required'),
    rememberMe: z.boolean().optional().default(false),
    captchaToken: z.string().optional(),
  }),

  /**
   * Refresh token validator
   * Validates token refresh request
   */
  refreshToken: z.object({
    refreshToken: z.string().min(1, 'Refresh token is required'),
  }),

  /**
   * Verify email validator
   * Validates email verification request
   */
  verifyEmail: z.object({
    token: z.string().min(1, 'Verification token is required'),
  }),

  /**
   * Resend verification email validator
   * Validates request to resend verification email
   */
  resendVerification: z.object({
    email: emailSchema.optional(),
  }),

  /**
   * Forgot password validator
   * Validates forgot password request
   */
  forgotPassword: z.object({
    email: emailSchema,
    captchaToken: z.string().optional(),
  }),

  /**
   * Reset password validator
   * Validates password reset request
   */
  resetPassword: z
    .object({
      token: z.string().min(1, 'Reset token is required'),
      password: passwordSchema,
      confirmPassword: z.string().min(1, 'Confirm password is required'),
    })
    .refine(data => data.password === data.confirmPassword, {
      message: 'Passwords do not match',
      path: ['confirmPassword'],
    }),

  /**
   * Change password validator
   * Validates password change request
   */
  changePassword: z
    .object({
      currentPassword: z.string().min(1, 'Current password is required'),
      newPassword: passwordSchema,
      confirmPassword: z.string().min(1, 'Confirm password is required'),
    })
    .refine(data => data.newPassword === data.confirmPassword, {
      message: 'Passwords do not match',
      path: ['confirmPassword'],
    })
    .refine(data => data.currentPassword !== data.newPassword, {
      message: 'New password must be different from current password',
      path: ['newPassword'],
    }),

  /**
   * Update profile validator
   * Validates user profile update request
   */
  updateProfile: z.object({
    username: usernameSchema.optional(),
    firstName: z.string().max(50, 'First name is too long').optional(),
    lastName: z.string().max(50, 'Last name is too long').optional(),
    phoneNumber: z
      .string()
      .regex(/^\+[1-9]\d{1,14}$/, 'Phone number must be in E.164 format')
      .optional(),
    displayName: z.string().max(100, 'Display name is too long').optional(),
    bio: z.string().max(500, 'Bio is too long').optional(),
    avatarUrl: z.string().url('Invalid URL format').optional().nullable(),
  }),

  /**
   * Update email validator
   * Validates email update request
   */
  updateEmail: z.object({
    email: emailSchema,
    password: z.string().min(1, 'Password is required'),
  }),

  /**
   * Verify phone number validator
   * Validates phone verification request
   */
  verifyPhone: z.object({
    code: z.string().min(4, 'Verification code is required').max(10, 'Invalid verification code'),
  }),

  /**
   * Get sessions validator
   * Validates request to retrieve user sessions
   */
  getSessions: z.object({
    includeInactive: z.boolean().optional().default(false),
  }),

  /**
   * Terminate session validator
   * Validates request to terminate a session
   */
  terminateSession: z.object({
    sessionId: z.string().min(1, 'Session ID is required'),
  }),

  /**
   * Logout validator
   * Validates logout request
   */
  logout: z.object({
    sessionId: z.string().optional(),
    allSessions: z.boolean().optional().default(false),
  }),

  /**
   * Social login validator
   * Validates social login request
   */
  socialLogin: z.object({
    provider: z.enum(['google', 'facebook', 'apple', 'github', 'twitter', 'linkedin']),
    token: z.string().min(1, 'Provider token is required'),
    redirectUri: z.string().url('Invalid redirect URI').optional(),
  }),

  /**
   * Link social account validator
   * Validates request to link a social account
   */
  linkSocialAccount: z.object({
    provider: z.enum(['google', 'facebook', 'apple', 'github', 'twitter', 'linkedin']),
    token: z.string().min(1, 'Provider token is required'),
  }),

  /**
   * Unlink social account validator
   * Validates request to unlink a social account
   */
  unlinkSocialAccount: z.object({
    provider: z.enum(['google', 'facebook', 'apple', 'github', 'twitter', 'linkedin']),
  }),

  /**
   * Request account deletion validator
   * Validates request to delete user account
   */
  requestAccountDeletion: z.object({
    password: z.string().min(1, 'Password is required'),
    reason: z.string().max(1000, 'Reason is too long').optional(),
    confirmPhrase: z.literal('DELETE MY ACCOUNT'),
  }),

  /**
   * Cancel account deletion validator
   * Validates request to cancel account deletion
   */
  cancelAccountDeletion: z.object({
    token: z.string().min(1, 'Cancellation token is required'),
  }),

  /**
   * Update user preferences validator
   * Validates request to update user preferences
   */
  updatePreferences: z.object({
    preferences: z.record(z.any()),
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
      additionalChecks?: (data: any, context?: AuthValidationContext) => boolean | Promise<boolean>;
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
   * Password strength validator
   * Validates password strength and returns a score
   */
  validatePasswordStrength: (
    password: string
  ): {
    score: number; // 0-4, where 0 is very weak and 4 is very strong
    feedback: string[];
    isStrong: boolean;
  } => {
    const feedback = [];
    let score = 0;

    // Length check
    if (password.length >= 12) {
      score += 1;
    } else if (password.length >= 8) {
      score += 0.5;
    } else {
      feedback.push('Password should be at least 8 characters long');
    }

    // Character variety checks
    if (/[a-z]/.test(password)) score += 0.5;
    else feedback.push('Add lowercase letters');

    if (/[A-Z]/.test(password)) score += 0.5;
    else feedback.push('Add uppercase letters');

    if (/[0-9]/.test(password)) score += 0.5;
    else feedback.push('Add numbers');

    if (/[^a-zA-Z0-9]/.test(password)) score += 0.5;
    else feedback.push('Add special characters');

    // Complexity checks
    if (/(.)\1{2,}/.test(password)) {
      score -= 0.5;
      feedback.push('Avoid repeated characters');
    }

    if (/^(?:abc|123|qwerty|password|admin|welcome)/i.test(password)) {
      score -= 1;
      feedback.push('Avoid common password patterns');
    }

    // Normalize score to 0-4 range
    score = Math.max(0, Math.min(4, score));

    return {
      score,
      feedback,
      isStrong: score >= 3,
    };
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
