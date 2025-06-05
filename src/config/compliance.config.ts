import dotenv from 'dotenv';
import path from 'path';
import { validateConfig } from '../utils/validation';
import { validateEnvVars } from '../utils/env-validator';
import { z } from 'zod';

// Load environment variables from .env file
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

// Helper functions for environment variable access
// function getEnvVar(key: string, defaultValue?: string): string {
//   return process.env[key] || defaultValue || '';
// }

function getEnvBoolean(key: string, defaultValue = false): boolean {
  const value = process.env[key];
  if (value === 'true') return true;
  if (value === 'false') return false;
  return defaultValue;
}

function getEnvNumber(key: string, defaultValue: number): number {
  const value = Number(process.env[key]);
  return isNaN(value) ? defaultValue : value;
}

// Define compliance config schema with Zod
const complianceConfigSchema = z.object({
  gdpr: z.object({
    enabled: z.boolean().default(true),
    dataRetention: z.object({
      userAccounts: z
        .number()
        .int()
        .positive()
        .default(365 * 2), // 2 years
      userActivity: z.number().int().positive().default(365), // 1 year
      auditLogs: z
        .number()
        .int()
        .positive()
        .default(365 * 3), // 3 years
      backups: z.number().int().positive().default(90), // 90 days
    }),
    dataSubjectRights: z.object({
      accessRequestEnabled: z.boolean().default(true),
      deletionRequestEnabled: z.boolean().default(true),
      rectificationRequestEnabled: z.boolean().default(true),
      restrictionRequestEnabled: z.boolean().default(true),
      portabilityRequestEnabled: z.boolean().default(true),
      objectionRequestEnabled: z.boolean().default(true),
      verificationRequired: z.boolean().default(true),
      processingTimeLimit: z.number().int().positive().default(30), // 30 days
    }),
    verification: z.object({
      tokenTtl: z
        .number()
        .int()
        .positive()
        .default(24 * 60 * 60), // 24 hours
      emailVerificationRequired: z.boolean().default(true),
      phoneVerificationEnabled: z.boolean().default(false),
    }),
    dataProtection: z.object({
      pseudonymizationEnabled: z.boolean().default(true),
      anonymizationEnabled: z.boolean().default(true),
      encryptionRequired: z.boolean().default(true),
      dataMinimizationEnabled: z.boolean().default(true),
    }),
    consent: z.object({
      required: z.boolean().default(true),
      expiration: z.number().int().nonnegative().default(365), // 1 year
      recordsRetention: z
        .number()
        .int()
        .positive()
        .default(365 * 5), // 5 years
    }),
    breach: z.object({
      notificationEnabled: z.boolean().default(true),
      notificationDeadline: z.number().int().positive().default(72), // 72 hours
      recordsRetention: z
        .number()
        .int()
        .positive()
        .default(365 * 5), // 5 years
    }),
  }),
  ccpa: z.object({
    enabled: z.boolean().default(true),
    doNotSellEnabled: z.boolean().default(true),
    optOutEnabled: z.boolean().default(true),
    dataRetention: z.number().int().positive().default(365), // 1 year
  }),
  hipaa: z.object({
    enabled: z.boolean().default(false),
    dataRetention: z
      .number()
      .int()
      .positive()
      .default(365 * 6), // 6 years
    auditRetention: z
      .number()
      .int()
      .positive()
      .default(365 * 6), // 6 years
  }),
  pci: z.object({
    enabled: z.boolean().default(false),
    dataRetention: z.number().int().positive().default(365), // 1 year
    maskingEnabled: z.boolean().default(true),
  }),
  reporting: z.object({
    enabled: z.boolean().default(true),
    scheduledReports: z.boolean().default(true),
    reportRetention: z
      .number()
      .int()
      .positive()
      .default(365 * 2), // 2 years
  }),
});

// Parse and validate environment variables
const rawConfig = {
  gdpr: {
    enabled: getEnvBoolean('COMPLIANCE_GDPR_ENABLED', true),
    dataRetention: {
      userAccounts: getEnvNumber('COMPLIANCE_GDPR_RETENTION_USER_ACCOUNTS', 365 * 2),
      userActivity: getEnvNumber('COMPLIANCE_GDPR_RETENTION_USER_ACTIVITY', 365),
      auditLogs: getEnvNumber('COMPLIANCE_GDPR_RETENTION_AUDIT_LOGS', 365 * 3),
      backups: getEnvNumber('COMPLIANCE_GDPR_RETENTION_BACKUPS', 90),
    },
    dataSubjectRights: {
      accessRequestEnabled: getEnvBoolean('COMPLIANCE_GDPR_ACCESS_REQUEST_ENABLED', true),
      deletionRequestEnabled: getEnvBoolean('COMPLIANCE_GDPR_DELETION_REQUEST_ENABLED', true),
      rectificationRequestEnabled: getEnvBoolean(
        'COMPLIANCE_GDPR_RECTIFICATION_REQUEST_ENABLED',
        true
      ),
      restrictionRequestEnabled: getEnvBoolean('COMPLIANCE_GDPR_RESTRICTION_REQUEST_ENABLED', true),
      portabilityRequestEnabled: getEnvBoolean('COMPLIANCE_GDPR_PORTABILITY_REQUEST_ENABLED', true),
      objectionRequestEnabled: getEnvBoolean('COMPLIANCE_GDPR_OBJECTION_REQUEST_ENABLED', true),
      verificationRequired: getEnvBoolean('COMPLIANCE_GDPR_VERIFICATION_REQUIRED', true),
      processingTimeLimit: getEnvNumber('COMPLIANCE_GDPR_PROCESSING_TIME_LIMIT', 30),
    },
    verification: {
      tokenTtl: getEnvNumber('COMPLIANCE_GDPR_VERIFICATION_TOKEN_TTL', 24 * 60 * 60),
      emailVerificationRequired: getEnvBoolean('COMPLIANCE_GDPR_EMAIL_VERIFICATION_REQUIRED', true),
      phoneVerificationEnabled: getEnvBoolean('COMPLIANCE_GDPR_PHONE_VERIFICATION_ENABLED', false),
    },
    dataProtection: {
      pseudonymizationEnabled: getEnvBoolean('COMPLIANCE_GDPR_PSEUDONYMIZATION_ENABLED', true),
      anonymizationEnabled: getEnvBoolean('COMPLIANCE_GDPR_ANONYMIZATION_ENABLED', true),
      encryptionRequired: getEnvBoolean('COMPLIANCE_GDPR_ENCRYPTION_REQUIRED', true),
      dataMinimizationEnabled: getEnvBoolean('COMPLIANCE_GDPR_DATA_MINIMIZATION_ENABLED', true),
    },
    consent: {
      required: getEnvBoolean('COMPLIANCE_GDPR_CONSENT_REQUIRED', true),
      expiration: getEnvNumber('COMPLIANCE_GDPR_CONSENT_EXPIRATION', 365),
      recordsRetention: getEnvNumber('COMPLIANCE_GDPR_CONSENT_RECORDS_RETENTION', 365 * 5),
    },
    breach: {
      notificationEnabled: getEnvBoolean('COMPLIANCE_GDPR_BREACH_NOTIFICATION_ENABLED', true),
      notificationDeadline: getEnvNumber('COMPLIANCE_GDPR_BREACH_NOTIFICATION_DEADLINE', 72),
      recordsRetention: getEnvNumber('COMPLIANCE_GDPR_BREACH_RECORDS_RETENTION', 365 * 5),
    },
  },
  ccpa: {
    enabled: getEnvBoolean('COMPLIANCE_CCPA_ENABLED', true),
    doNotSellEnabled: getEnvBoolean('COMPLIANCE_CCPA_DO_NOT_SELL_ENABLED', true),
    optOutEnabled: getEnvBoolean('COMPLIANCE_CCPA_OPT_OUT_ENABLED', true),
    dataRetention: getEnvNumber('COMPLIANCE_CCPA_DATA_RETENTION', 365),
  },
  hipaa: {
    enabled: getEnvBoolean('COMPLIANCE_HIPAA_ENABLED', false),
    dataRetention: getEnvNumber('COMPLIANCE_HIPAA_DATA_RETENTION', 365 * 6),
    auditRetention: getEnvNumber('COMPLIANCE_HIPAA_AUDIT_RETENTION', 365 * 6),
  },
  pci: {
    enabled: getEnvBoolean('COMPLIANCE_PCI_ENABLED', false),
    dataRetention: getEnvNumber('COMPLIANCE_PCI_DATA_RETENTION', 365),
    maskingEnabled: getEnvBoolean('COMPLIANCE_PCI_MASKING_ENABLED', true),
  },
  reporting: {
    enabled: getEnvBoolean('COMPLIANCE_REPORTING_ENABLED', true),
    scheduledReports: getEnvBoolean('COMPLIANCE_SCHEDULED_REPORTS_ENABLED', true),
    reportRetention: getEnvNumber('COMPLIANCE_REPORT_RETENTION', 365 * 2),
  },
};

// Define critical environment variables that must be present
const requiredEnvVars: string[] = ['COMPLIANCE_GDPR_ENABLED'];

// Define optional environment variables
const optionalEnvVars: string[] = [
  'COMPLIANCE_GDPR_RETENTION_USER_ACCOUNTS',
  'COMPLIANCE_GDPR_RETENTION_USER_ACTIVITY',
  'COMPLIANCE_GDPR_RETENTION_AUDIT_LOGS',
  'COMPLIANCE_GDPR_RETENTION_BACKUPS',
  'COMPLIANCE_GDPR_ACCESS_REQUEST_ENABLED',
  'COMPLIANCE_GDPR_DELETION_REQUEST_ENABLED',
  'COMPLIANCE_GDPR_RECTIFICATION_REQUEST_ENABLED',
  'COMPLIANCE_GDPR_RESTRICTION_REQUEST_ENABLED',
  'COMPLIANCE_GDPR_PORTABILITY_REQUEST_ENABLED',
  'COMPLIANCE_GDPR_OBJECTION_REQUEST_ENABLED',
  'COMPLIANCE_GDPR_VERIFICATION_REQUIRED',
  'COMPLIANCE_GDPR_PROCESSING_TIME_LIMIT',
  'COMPLIANCE_GDPR_VERIFICATION_TOKEN_TTL',
  'COMPLIANCE_GDPR_EMAIL_VERIFICATION_REQUIRED',
  'COMPLIANCE_GDPR_PHONE_VERIFICATION_ENABLED',
  'COMPLIANCE_GDPR_PSEUDONYMIZATION_ENABLED',
  'COMPLIANCE_GDPR_ANONYMIZATION_ENABLED',
  'COMPLIANCE_GDPR_ENCRYPTION_REQUIRED',
  'COMPLIANCE_GDPR_DATA_MINIMIZATION_ENABLED',
  'COMPLIANCE_GDPR_CONSENT_REQUIRED',
  'COMPLIANCE_GDPR_CONSENT_EXPIRATION',
  'COMPLIANCE_GDPR_CONSENT_RECORDS_RETENTION',
  'COMPLIANCE_GDPR_BREACH_NOTIFICATION_ENABLED',
  'COMPLIANCE_GDPR_BREACH_NOTIFICATION_DEADLINE',
  'COMPLIANCE_GDPR_BREACH_RECORDS_RETENTION',
  'COMPLIANCE_CCPA_ENABLED',
  'COMPLIANCE_CCPA_DO_NOT_SELL_ENABLED',
  'COMPLIANCE_CCPA_OPT_OUT_ENABLED',
  'COMPLIANCE_CCPA_DATA_RETENTION',
  'COMPLIANCE_HIPAA_ENABLED',
  'COMPLIANCE_HIPAA_DATA_RETENTION',
  'COMPLIANCE_HIPAA_AUDIT_RETENTION',
  'COMPLIANCE_PCI_ENABLED',
  'COMPLIANCE_PCI_DATA_RETENTION',
  'COMPLIANCE_PCI_MASKING_ENABLED',
  'COMPLIANCE_REPORTING_ENABLED',
  'COMPLIANCE_SCHEDULED_REPORTS_ENABLED',
  'COMPLIANCE_REPORT_RETENTION',
];

// Validate environment variables
validateEnvVars(requiredEnvVars, optionalEnvVars);

// Validate and export config
export const complianceConfig = validateConfig(complianceConfigSchema, rawConfig);

// Export config type
export type ComplianceConfig = typeof complianceConfig;
