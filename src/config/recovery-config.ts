import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define recovery config schema with Zod
const recoveryConfigSchema = z.object({
  email: z.object({
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
  }),
  securityQuestions: z.object({
    minQuestions: z.number().int().positive().default(3),
    minAnswerLength: z.number().int().positive().default(3),
    maxAnswerLength: z.number().int().positive().default(100),
    maxAttempts: z.number().int().positive().default(5),
    lockoutPeriod: z
      .number()
      .int()
      .positive()
      .default(30 * 60), // 30 minutes
  }),
  trustedContacts: z.object({
    minContacts: z.number().int().positive().default(1),
    maxContacts: z.number().int().positive().default(3),
    verificationCodeLength: z.number().int().min(6).max(12).default(8),
    tokenExpiration: z
      .number()
      .int()
      .positive()
      .default(24 * 60 * 60), // 24 hours
    maxAttempts: z.number().int().positive().default(3),
  }),
  adminRecovery: z.object({
    requireApprovalCount: z.number().int().positive().default(2),
    tokenExpiration: z
      .number()
      .int()
      .positive()
      .default(60 * 60), // 1 hour
    notificationChannels: z.array(z.string()).default(['email', 'sms']),
  }),
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
  }),
});

// Parse and validate environment variables
const rawConfig = {
  email: {
    tokenExpiration: env.getNumber('RECOVERY_EMAIL_TOKEN_EXPIRATION'),
    maxAttempts: env.getNumber('RECOVERY_EMAIL_MAX_ATTEMPTS'),
    cooldownPeriod: env.getNumber('RECOVERY_EMAIL_COOLDOWN_PERIOD'),
    verificationCodeLength: env.getNumber('RECOVERY_EMAIL_VERIFICATION_CODE_LENGTH'),
  },
  securityQuestions: {
    minQuestions: env.getNumber('RECOVERY_SECURITY_QUESTIONS_MIN'),
    minAnswerLength: env.getNumber('RECOVERY_SECURITY_QUESTIONS_MIN_ANSWER_LENGTH'),
    maxAnswerLength: env.getNumber('RECOVERY_SECURITY_QUESTIONS_MAX_ANSWER_LENGTH'),
    maxAttempts: env.getNumber('RECOVERY_SECURITY_QUESTIONS_MAX_ATTEMPTS'),
    lockoutPeriod: env.getNumber('RECOVERY_SECURITY_QUESTIONS_LOCKOUT_PERIOD'),
  },
  trustedContacts: {
    minContacts: env.getNumber('RECOVERY_TRUSTED_CONTACTS_MIN'),
    maxContacts: env.getNumber('RECOVERY_TRUSTED_CONTACTS_MAX'),
    verificationCodeLength: env.getNumber('RECOVERY_TRUSTED_CONTACTS_VERIFICATION_CODE_LENGTH'),
    tokenExpiration: env.getNumber('RECOVERY_TRUSTED_CONTACTS_TOKEN_EXPIRATION'),
    maxAttempts: env.getNumber('RECOVERY_TRUSTED_CONTACTS_MAX_ATTEMPTS'),
  },
  adminRecovery: {
    requireApprovalCount: env.getNumber('RECOVERY_ADMIN_REQUIRE_APPROVAL_COUNT'),
    tokenExpiration: env.getNumber('RECOVERY_ADMIN_TOKEN_EXPIRATION'),
    notificationChannels: env.get('RECOVERY_ADMIN_NOTIFICATION_CHANNELS')?.split(','),
  },
  general: {
    recoveryTokenLength: env.getNumber('RECOVERY_TOKEN_LENGTH'),
    recoveryTokenExpiration: env.getNumber('RECOVERY_TOKEN_EXPIRATION'),
    maxConcurrentRecoveries: env.getNumber('RECOVERY_MAX_CONCURRENT'),
    cooldownBetweenRecoveries: env.getNumber('RECOVERY_COOLDOWN_BETWEEN'),
    notifyUserOnRecovery: env.getBoolean('RECOVERY_NOTIFY_USER'),
    notifyAdminOnRecovery: env.getBoolean('RECOVERY_NOTIFY_ADMIN'),
  },
};

// Validate and export config
export const recoveryConfig = validateConfig(recoveryConfigSchema, rawConfig);

// Export config type
export type RecoveryConfig = typeof recoveryConfig;
