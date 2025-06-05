import { validateConfig } from '../utils/validation';
import { z } from 'zod';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define audit config schema with Zod
const auditConfigSchema = z.object({
  enabled: z.boolean().default(true),
  logLevel: z.enum(['debug', 'info', 'warning', 'error', 'critical']).default('info'),
  retention: z.object({
    enabled: z.boolean().default(true),
    period: z.number().int().positive().default(365), // days
    archiveEnabled: z.boolean().default(true),
    archivePeriod: z.number().int().positive().default(730), // days
  }),
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
  redaction: z.object({
    enabled: z.boolean().default(true),
    fields: z
      .array(z.string())
      .default(['password', 'secret', 'token', 'apiKey', 'creditCard', 'ssn']),
  }),
  events: z.object({
    authentication: z.boolean().default(true),
    authorization: z.boolean().default(true),
    dataAccess: z.boolean().default(true),
    systemChanges: z.boolean().default(true),
    userManagement: z.boolean().default(true),
  }),
  alerting: z.object({
    enabled: z.boolean().default(false),
    endpoints: z.array(z.string()).default([]),
    criticalOnly: z.boolean().default(true),
  }),
  performance: z.object({
    batchSize: z.number().int().positive().default(100),
    flushInterval: z.number().int().positive().default(5000), // 5 seconds
    asyncProcessing: z.boolean().default(true),
  }),
});

// Parse and validate environment variables
const rawConfig = {
  enabled: env.getBoolean('AUDIT_ENABLED', true),
  logLevel: env.get('AUDIT_LOG_LEVEL', 'info'),
  retention: {
    enabled: env.getBoolean('AUDIT_RETENTION_ENABLED', true),
    period: env.getNumber('AUDIT_RETENTION_PERIOD', 365),
    archiveEnabled: env.getBoolean('AUDIT_ARCHIVE_ENABLED', true),
    archivePeriod: env.getNumber('AUDIT_ARCHIVE_PERIOD', 730),
  },
  storage: {
    type: env.get('AUDIT_STORAGE_TYPE', 'database'),
    path: env.get('AUDIT_STORAGE_PATH'),
    rotationEnabled: env.getBoolean('AUDIT_ROTATION_ENABLED', true),
    rotationSize: env.getNumber('AUDIT_ROTATION_SIZE', 10 * 1024 * 1024),
    rotationPeriod: env.getNumber('AUDIT_ROTATION_PERIOD', 7),
  },
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
  },
  events: {
    authentication: env.getBoolean('AUDIT_EVENTS_AUTHENTICATION', true),
    authorization: env.getBoolean('AUDIT_EVENTS_AUTHORIZATION', true),
    dataAccess: env.getBoolean('AUDIT_EVENTS_DATA_ACCESS', true),
    systemChanges: env.getBoolean('AUDIT_EVENTS_SYSTEM_CHANGES', true),
    userManagement: env.getBoolean('AUDIT_EVENTS_USER_MANAGEMENT', true),
  },
  alerting: {
    enabled: env.getBoolean('AUDIT_ALERTING_ENABLED', false),
    endpoints: env.get('AUDIT_ALERTING_ENDPOINTS')?.split(',') || [],
    criticalOnly: env.getBoolean('AUDIT_ALERTING_CRITICAL_ONLY', true),
  },
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
