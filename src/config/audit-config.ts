import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define audit config schema with Zod
const auditConfigSchema = z.object({
  // General settings
  enabled: z.boolean().default(true),
  logLevel: z.enum(['debug', 'info', 'warning', 'error', 'critical']).default('info'),

  // Retention settings
  retention: z.object({
    enabled: z.boolean().default(true),
    period: z.number().int().positive().default(365), // days
    retentionPeriod: z.number().int().positive().default(365), // days (alias for period)
    archiveEnabled: z.boolean().default(true),
    archivePeriod: z.number().int().positive().default(730), // days
    enableArchiving: z.boolean().default(false),
    archiveFrequency: z.number().int().positive().default(30), // days
    archiveLocation: z.string().default('s3://audit-logs-archive'),
  }),

  // Storage settings
  storage: z.object({
    type: z.enum(['database', 'file', 'external']).default('database'),
    path: z.string().optional(),
    rotationEnabled: z.boolean().default(true),
    rotationSize: z
      .number()
      .int()
      .positive()
      .default(10 * 1024 * 1024), // 10MB
    rotationPeriod: z.number().int().positive().default(7), // days
  }),

  // Redaction settings
  redaction: z.object({
    enabled: z.boolean().default(true),
    fields: z
      .array(z.string())
      .default(['password', 'secret', 'token', 'apiKey', 'creditCard', 'ssn']),
    logSensitiveData: z.boolean().default(false),
    logRequestBodies: z.boolean().default(false),
    logResponseBodies: z.boolean().default(false),
    maxMetadataSize: z.number().int().positive().default(10240), // 10KB
  }),

  // Event settings
  events: z.object({
    authentication: z.boolean().default(true),
    authorization: z.boolean().default(true),
    dataAccess: z.boolean().default(true),
    systemChanges: z.boolean().default(true),
    userManagement: z.boolean().default(true),
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
  }),

  // Alerting settings
  alerting: z.object({
    enabled: z.boolean().default(false),
    endpoints: z.array(z.string()).default([]),
    criticalOnly: z.boolean().default(true),
    enableAlerts: z.boolean().default(false),
    alertEmail: z.string().email().default('security@example.com'),
  }),

  // Performance settings
  performance: z.object({
    batchSize: z.number().int().positive().default(100),
    flushInterval: z.number().int().positive().default(5000), // 5 seconds
    asyncProcessing: z.boolean().default(true),
  }),
});

// Parse and validate environment variables
const rawConfig = {
  // General settings
  enabled: env.getBoolean('AUDIT_ENABLED', true),
  logLevel: env.get('AUDIT_LOG_LEVEL', 'info'),

  // Retention settings
  retention: {
    enabled: env.getBoolean('AUDIT_RETENTION_ENABLED', true),
    period: env.getNumber('AUDIT_RETENTION_PERIOD', 365),
    retentionPeriod: env.getNumber('AUDIT_RETENTION_PERIOD', 365),
    archiveEnabled: env.getBoolean('AUDIT_ARCHIVE_ENABLED', true),
    archivePeriod: env.getNumber('AUDIT_ARCHIVE_PERIOD', 730),
    enableArchiving: env.getBoolean('AUDIT_ENABLE_ARCHIVING', false),
    archiveFrequency: env.getNumber('AUDIT_ARCHIVE_FREQUENCY', 30),
    archiveLocation: env.get('AUDIT_ARCHIVE_LOCATION', 's3://audit-logs-archive'),
  },

  // Storage settings
  storage: {
    type: env.get('AUDIT_STORAGE_TYPE', 'database'),
    path: env.get('AUDIT_STORAGE_PATH'),
    rotationEnabled: env.getBoolean('AUDIT_ROTATION_ENABLED', true),
    rotationSize: env.getNumber('AUDIT_ROTATION_SIZE', 10 * 1024 * 1024),
    rotationPeriod: env.getNumber('AUDIT_ROTATION_PERIOD', 7),
  },

  // Redaction settings
  redaction: {
    enabled: env.getBoolean('AUDIT_REDACTION_ENABLED', true),
    fields: env.get('AUDIT_REDACTION_FIELDS')?.split(',') || [
      'password',
      'secret',
      'token',
      'apiKey',
      'creditCard',
      'ssn',
    ],
    logSensitiveData: env.getBoolean('AUDIT_LOG_SENSITIVE_DATA', false),
    logRequestBodies: env.getBoolean('AUDIT_LOG_REQUEST_BODIES', false),
    logResponseBodies: env.getBoolean('AUDIT_LOG_RESPONSE_BODIES', false),
    maxMetadataSize: env.getNumber('AUDIT_MAX_METADATA_SIZE', 10240),
  },

  // Event settings
  events: {
    authentication: env.getBoolean('AUDIT_EVENTS_AUTHENTICATION', true),
    authorization: env.getBoolean('AUDIT_EVENTS_AUTHORIZATION', true),
    dataAccess: env.getBoolean('AUDIT_EVENTS_DATA_ACCESS', true),
    systemChanges: env.getBoolean('AUDIT_EVENTS_SYSTEM_CHANGES', true),
    userManagement: env.getBoolean('AUDIT_EVENTS_USER_MANAGEMENT', true),
    criticalActions: env.get('AUDIT_CRITICAL_ACTIONS')?.split(',') || [
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
    ],
    excludedActions: env.get('AUDIT_EXCLUDED_ACTIONS')?.split(',') || [
      'HEALTH_CHECK',
      'METRICS_COLLECTED',
      'AUDIT_LOG_VIEWED',
    ],
  },

  // Alerting settings
  alerting: {
    enabled: env.getBoolean('AUDIT_ALERTING_ENABLED', false),
    endpoints: env.get('AUDIT_ALERTING_ENDPOINTS')?.split(',') || [],
    criticalOnly: env.getBoolean('AUDIT_ALERTING_CRITICAL_ONLY', true),
    enableAlerts: env.getBoolean('AUDIT_ENABLE_ALERTS', false),
    alertEmail: env.get('AUDIT_ALERT_EMAIL', 'security@example.com'),
  },

  // Performance settings
  performance: {
    batchSize: env.getNumber('AUDIT_PERFORMANCE_BATCH_SIZE', 100),
    flushInterval: env.getNumber('AUDIT_PERFORMANCE_FLUSH_INTERVAL', 5000),
    asyncProcessing: env.getBoolean('AUDIT_PERFORMANCE_ASYNC_PROCESSING', true),
  },
};

// Validate and export config
export const auditConfig = validateConfig(auditConfigSchema, rawConfig);

// Export config type
export type AuditConfig = typeof auditConfig;

// Export for backward compatibility
export { auditConfig as auditConfiguration };
