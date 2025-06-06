import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define recovery config schema with Zod
const recoveryConfigSchema = z.object({
  // Email recovery settings
  email: z.object({
    enabled: z.boolean().default(true),
    tokenExpiration: z
      .number()
      .int()
      .positive()
      .default(60 * 60), // 1 hour
    maxAttempts: z.number().int().positive().default(3),
    cooldownPeriod: z
      .number()
      .int()
      .positive()
      .default(15 * 60), // 15 minutes
    verificationCodeLength: z.number().int().min(6).max(12).default(8),
    codeLength: z.number().int().min(6).max(12).default(6),
    numericCodesOnly: z.boolean().default(true),
    useSecureToken: z.boolean().default(false),
    codeExpiration: z.number().int().positive().default(900), // 15 minutes
    maxVerificationAttempts: z.number().int().positive().default(5),
    enforceRateLimit: z.boolean().default(true),
    rateLimitWindow: z.number().int().positive().default(3600), // 1 hour
    rateLimitMaxAttempts: z.number().int().positive().default(5),
  }),

  // Security questions settings
  securityQuestions: z.object({
    enabled: z.boolean().default(true),
    minQuestions: z.number().int().positive().default(3),
    minAnswerLength: z.number().int().positive().default(3),
    maxAnswerLength: z.number().int().positive().default(100),
    maxAttempts: z.number().int().positive().default(5),
    lockoutPeriod: z
      .number()
      .int()
      .positive()
      .default(30 * 60), // 30 minutes
    questionsToAsk: z.number().int().positive().default(3),
    minCorrectAnswers: z.number().int().positive().default(2),
    enforceMinAnswerLength: z.boolean().default(true),
    useFuzzyMatching: z.boolean().default(true),
    fuzzyMatchThreshold: z.number().min(0).max(1).default(0.8),
    rotateQuestionsAfterUse: z.boolean().default(true),
  }),

  // Trusted contacts settings
  trustedContacts: z.object({
    enabled: z.boolean().default(true),
    minContacts: z.number().int().positive().default(1),
    maxContacts: z.number().int().positive().default(3),
    verificationCodeLength: z.number().int().min(6).max(12).default(8),
    tokenExpiration: z
      .number()
      .int()
      .positive()
      .default(24 * 60 * 60), // 24 hours
    maxAttempts: z.number().int().positive().default(3),
    minContactsForRecovery: z.number().int().positive().default(1),
    codeLength: z.number().int().min(6).max(12).default(8),
    codeExpiration: z.number().int().positive().default(86400), // 24 hours
    requireMultipleApprovals: z.boolean().default(false),
    requiredApprovals: z.number().int().positive().default(2),
  }),

  // Admin recovery settings
  adminRecovery: z.object({
    enabled: z.boolean().default(true),
    requireApprovalCount: z.number().int().positive().default(2),
    tokenExpiration: z
      .number()
      .int()
      .positive()
      .default(60 * 60), // 1 hour
    notificationChannels: z.array(z.string()).default(['email', 'sms']),
    minApproverRole: z.string().default('ADMIN'), // "ADMIN" or "SUPER_ADMIN"
    requireReason: z.boolean().default(true),
    requireMultipleApprovals: z.boolean().default(false),
    requiredApprovals: z.number().int().positive().default(2),
    notifyUserOnAdminRecovery: z.boolean().default(true),
  }),

  // Recovery codes settings
  recoveryCodes: z.object({
    enabled: z.boolean().default(true),
    codeCount: z.number().int().positive().default(10),
    codeLength: z.number().int().min(6).max(16).default(10),
    numericCodesOnly: z.boolean().default(false),
    enforceRateLimit: z.boolean().default(true),
    rateLimitWindow: z.number().int().positive().default(3600), // 1 hour
    rateLimitMaxAttempts: z.number().int().positive().default(5),
  }),

  // Multi-factor recovery settings
  multiFactorRecovery: z.object({
    requireMultipleMethodsForHighRisk: z.boolean().default(true),
    riskThreshold: z.number().min(0).max(1).default(0.7),
    requiredMethodCount: z.number().int().positive().default(2),
    allowProgressiveVerification: z.boolean().default(true),
  }),

  // General recovery settings
  general: z.object({
    recoveryTokenLength: z.number().int().min(32).max(128).default(64),
    recoveryTokenExpiration: z
      .number()
      .int()
      .positive()
      .default(24 * 60 * 60), // 24 hours
    maxConcurrentRecoveries: z.number().int().positive().default(1),
    cooldownBetweenRecoveries: z
      .number()
      .int()
      .positive()
      .default(24 * 60 * 60), // 24 hours
    notifyUserOnRecovery: z.boolean().default(true),
    notifyAdminOnRecovery: z.boolean().default(true),
    riskThreshold: z.number().min(0).max(1).default(0.7),
  }),
});

// Parse and validate environment variables
const rawConfig = {
  // Email recovery settings
  email: {
    enabled: env.getBoolean('RECOVERY_EMAIL_ENABLED', true),
    tokenExpiration: env.getNumber('RECOVERY_EMAIL_TOKEN_EXPIRATION', 60 * 60),
    maxAttempts: env.getNumber('RECOVERY_EMAIL_MAX_ATTEMPTS', 3),
    cooldownPeriod: env.getNumber('RECOVERY_EMAIL_COOLDOWN_PERIOD', 15 * 60),
    verificationCodeLength: env.getNumber('RECOVERY_EMAIL_VERIFICATION_CODE_LENGTH', 8),
    codeLength: env.getNumber('RECOVERY_EMAIL_CODE_LENGTH', 6),
    numericCodesOnly: env.getBoolean('RECOVERY_EMAIL_NUMERIC_CODES_ONLY', true),
    useSecureToken: env.getBoolean('RECOVERY_EMAIL_USE_SECURE_TOKEN', false),
    codeExpiration: env.getNumber('RECOVERY_EMAIL_CODE_EXPIRATION', 900),
    maxVerificationAttempts: env.getNumber('RECOVERY_EMAIL_MAX_VERIFICATION_ATTEMPTS', 5),
    enforceRateLimit: env.getBoolean('RECOVERY_EMAIL_ENFORCE_RATE_LIMIT', true),
    rateLimitWindow: env.getNumber('RECOVERY_EMAIL_RATE_LIMIT_WINDOW', 3600),
    rateLimitMaxAttempts: env.getNumber('RECOVERY_EMAIL_RATE_LIMIT_MAX_ATTEMPTS', 5),
  },

  // Security questions settings
  securityQuestions: {
    enabled: env.getBoolean('RECOVERY_SECURITY_QUESTIONS_ENABLED', true),
    minQuestions: env.getNumber('RECOVERY_SECURITY_QUESTIONS_MIN', 3),
    minAnswerLength: env.getNumber('RECOVERY_SECURITY_QUESTIONS_MIN_ANSWER_LENGTH', 3),
    maxAnswerLength: env.getNumber('RECOVERY_SECURITY_QUESTIONS_MAX_ANSWER_LENGTH', 100),
    maxAttempts: env.getNumber('RECOVERY_SECURITY_QUESTIONS_MAX_ATTEMPTS', 5),
    lockoutPeriod: env.getNumber('RECOVERY_SECURITY_QUESTIONS_LOCKOUT_PERIOD', 30 * 60),
    questionsToAsk: env.getNumber('RECOVERY_SECURITY_QUESTIONS_TO_ASK', 3),
    minCorrectAnswers: env.getNumber('RECOVERY_SECURITY_QUESTIONS_MIN_CORRECT_ANSWERS', 2),
    enforceMinAnswerLength: env.getBoolean(
      'RECOVERY_SECURITY_QUESTIONS_ENFORCE_MIN_ANSWER_LENGTH',
      true
    ),
    useFuzzyMatching: env.getBoolean('RECOVERY_SECURITY_QUESTIONS_USE_FUZZY_MATCHING', true),
    fuzzyMatchThreshold: env.getNumber('RECOVERY_SECURITY_QUESTIONS_FUZZY_MATCH_THRESHOLD', 0.8),
    rotateQuestionsAfterUse: env.getBoolean('RECOVERY_SECURITY_QUESTIONS_ROTATE_AFTER_USE', true),
  },

  // Trusted contacts settings
  trustedContacts: {
    enabled: env.getBoolean('RECOVERY_TRUSTED_CONTACTS_ENABLED', true),
    minContacts: env.getNumber('RECOVERY_TRUSTED_CONTACTS_MIN', 1),
    maxContacts: env.getNumber('RECOVERY_TRUSTED_CONTACTS_MAX', 3),
    verificationCodeLength: env.getNumber('RECOVERY_TRUSTED_CONTACTS_VERIFICATION_CODE_LENGTH', 8),
    tokenExpiration: env.getNumber('RECOVERY_TRUSTED_CONTACTS_TOKEN_EXPIRATION', 24 * 60 * 60),
    maxAttempts: env.getNumber('RECOVERY_TRUSTED_CONTACTS_MAX_ATTEMPTS', 3),
    minContactsForRecovery: env.getNumber('RECOVERY_TRUSTED_CONTACTS_MIN_FOR_RECOVERY', 1),
    codeLength: env.getNumber('RECOVERY_TRUSTED_CONTACTS_CODE_LENGTH', 8),
    codeExpiration: env.getNumber('RECOVERY_TRUSTED_CONTACTS_CODE_EXPIRATION', 86400),
    requireMultipleApprovals: env.getBoolean(
      'RECOVERY_TRUSTED_CONTACTS_REQUIRE_MULTIPLE_APPROVALS',
      false
    ),
    requiredApprovals: env.getNumber('RECOVERY_TRUSTED_CONTACTS_REQUIRED_APPROVALS', 2),
  },

  // Admin recovery settings
  adminRecovery: {
    enabled: env.getBoolean('RECOVERY_ADMIN_ENABLED', true),
    requireApprovalCount: env.getNumber('RECOVERY_ADMIN_REQUIRE_APPROVAL_COUNT', 2),
    tokenExpiration: env.getNumber('RECOVERY_ADMIN_TOKEN_EXPIRATION', 60 * 60),
    notificationChannels: env.get('RECOVERY_ADMIN_NOTIFICATION_CHANNELS')?.split(',') || [
      'email',
      'sms',
    ],
    minApproverRole: env.get('RECOVERY_ADMIN_MIN_APPROVER_ROLE', 'ADMIN'),
    requireReason: env.getBoolean('RECOVERY_ADMIN_REQUIRE_REASON', true),
    requireMultipleApprovals: env.getBoolean('RECOVERY_ADMIN_REQUIRE_MULTIPLE_APPROVALS', false),
    requiredApprovals: env.getNumber('RECOVERY_ADMIN_REQUIRED_APPROVALS', 2),
    notifyUserOnAdminRecovery: env.getBoolean('RECOVERY_ADMIN_NOTIFY_USER', true),
  },

  // Recovery codes settings
  recoveryCodes: {
    enabled: env.getBoolean('RECOVERY_CODES_ENABLED', true),
    codeCount: env.getNumber('RECOVERY_CODES_COUNT', 10),
    codeLength: env.getNumber('RECOVERY_CODES_LENGTH', 10),
    numericCodesOnly: env.getBoolean('RECOVERY_CODES_NUMERIC_ONLY', false),
    enforceRateLimit: env.getBoolean('RECOVERY_CODES_ENFORCE_RATE_LIMIT', true),
    rateLimitWindow: env.getNumber('RECOVERY_CODES_RATE_LIMIT_WINDOW', 3600),
    rateLimitMaxAttempts: env.getNumber('RECOVERY_CODES_RATE_LIMIT_MAX_ATTEMPTS', 5),
  },

  // Multi-factor recovery settings
  multiFactorRecovery: {
    requireMultipleMethodsForHighRisk: env.getBoolean(
      'RECOVERY_MFA_REQUIRE_MULTIPLE_METHODS_HIGH_RISK',
      true
    ),
    riskThreshold: env.getNumber('RECOVERY_MFA_RISK_THRESHOLD', 0.7),
    requiredMethodCount: env.getNumber('RECOVERY_MFA_REQUIRED_METHOD_COUNT', 2),
    allowProgressiveVerification: env.getBoolean(
      'RECOVERY_MFA_ALLOW_PROGRESSIVE_VERIFICATION',
      true
    ),
  },

  // General recovery settings
  general: {
    recoveryTokenLength: env.getNumber('RECOVERY_TOKEN_LENGTH', 64),
    recoveryTokenExpiration: env.getNumber('RECOVERY_TOKEN_EXPIRATION', 24 * 60 * 60),
    maxConcurrentRecoveries: env.getNumber('RECOVERY_MAX_CONCURRENT', 1),
    cooldownBetweenRecoveries: env.getNumber('RECOVERY_COOLDOWN_BETWEEN', 24 * 60 * 60),
    notifyUserOnRecovery: env.getBoolean('RECOVERY_NOTIFY_USER', true),
    notifyAdminOnRecovery: env.getBoolean('RECOVERY_NOTIFY_ADMIN', true),
    riskThreshold: env.getNumber('RECOVERY_RISK_THRESHOLD', 0.7),
  },
};

// Validate and export config
export const recoveryConfig = validateConfig(recoveryConfigSchema, rawConfig);

// Export config type
export type RecoveryConfig = typeof recoveryConfig;

// Export for backward compatibility
export { recoveryConfig as recoveryConfiguration };
