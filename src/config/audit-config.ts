import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define audit config schema with Zod
const auditConfigSchema = z.object({
  enabled: z.boolean().default(true),
  retentionPeriod: z.number().int().positive().default(365), // 365 days
  logSensitiveData: z.boolean().default(false),
  logRequestBodies: z.boolean().default(false),
  logResponseBodies: z.boolean().default(false),
  maxMetadataSize: z.number().int().positive().default(10240), // 10KB
  criticalActions: z
    .array(z.string())
    .default([
      'USER_CREATED',
      'USER_DELETED',
      'USER_ENABLED',
      'USER_DISABLED',
      'ROLE_ASSIGNED',
      'ROLE_REMOVED',
      'PERMISSION_GRANTED',
      'PERMISSION_DENIED',
      'PASSWORD_CHANGED',
      'PASSWORD_RESET',
      'MFA_ENABLED',
      'MFA_DISABLED',
      'API_KEY_CREATED',
      'API_KEY_DELETED',
      'CONFIGURATION_CHANGED',
      'SYSTEM_SETTING_CHANGED',
    ]),
  excludedActions: z
    .array(z.string())
    .default(['HEALTH_CHECK', 'METRICS_COLLECTED', 'AUDIT_LOG_VIEWED']),
  enableAlerts: z.boolean().default(false),
  alertEmail: z.string().email().default('security@example.com'),
  enableArchiving: z.boolean().default(false),
  archiveFrequency: z.number().int().positive().default(30), // 30 days
  archiveLocation: z.string().default('s3://audit-logs-archive'),
});

// Parse and validate environment variables
const rawConfig = {
  enabled: env.getBoolean('AUDIT_ENABLED'),
  retentionPeriod: env.getNumber('AUDIT_RETENTION_PERIOD'),
  logSensitiveData: env.getBoolean('AUDIT_LOG_SENSITIVE_DATA'),
  logRequestBodies: env.getBoolean('AUDIT_LOG_REQUEST_BODIES'),
  logResponseBodies: env.getBoolean('AUDIT_LOG_RESPONSE_BODIES'),
  maxMetadataSize: env.getNumber('AUDIT_MAX_METADATA_SIZE'),
  criticalActions: env.get('AUDIT_CRITICAL_ACTIONS')?.split(','),
  excludedActions: env.get('AUDIT_EXCLUDED_ACTIONS')?.split(','),
  enableAlerts: env.getBoolean('AUDIT_ENABLE_ALERTS'),
  alertEmail: env.get('AUDIT_ALERT_EMAIL'),
  enableArchiving: env.getBoolean('AUDIT_ENABLE_ARCHIVING'),
  archiveFrequency: env.getNumber('AUDIT_ARCHIVE_FREQUENCY'),
  archiveLocation: env.get('AUDIT_ARCHIVE_LOCATION'),
};

// Validate and export config
export const auditConfig = validateConfig(auditConfigSchema, rawConfig);

// Export config type
export type AuditConfig = typeof auditConfig;
