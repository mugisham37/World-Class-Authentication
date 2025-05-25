// Export database connections
import {
  connectDatabase,
  disconnectDatabase,
  isDatabaseConnected,
  checkDatabaseHealth as checkPrismaHealth,
} from './prisma/client';

import {
  connectPostgres,
  disconnectPostgres,
  getPostgresStatus,
  query,
  transaction,
  pool,
} from './connections/postgres';

import {
  connectRedis,
  disconnectRedis,
  getRedisStatus,
  isRedisConnected,
  redisCache,
} from './connections/redis';

import { MetricsCollector } from './connections/metrics-collector';

import {
  createQueryBuilder,
  db as queryBuilder,
  QueryBuilder,
  QueryBuilderOptions,
} from './connections/query-builder';

import { ConnectionWrapper, db } from './connections/connection-wrapper';

import {
  ConnectionMonitor,
  connectionMonitor,
  HealthStatus,
  ConnectionMonitorOptions,
} from './connections/connection-monitor';

import {
  initializeDatabase,
  shutdownDatabase,
  getDatabaseHealth,
  isDatabaseConnected as isDbConnected,
} from './connections/database-manager';

// Export repositories
import { repositories } from './repositories';

// Export models
import * as UserModels from './models/user.model';
import * as CredentialModels from './models/credential.model';
import * as PasswordHistoryModels from './models/password-history.model';
import * as SessionModels from './models/session.model';
import * as MfaFactorModels from './models/mfa-factor.model';
import * as MfaChallengeModels from './models/mfa-challenge.model';
import * as RecoveryTokenModels from './models/recovery-token.model';
import * as RecoveryMethodModels from './models/recovery-method.model';
import * as RecoveryRequestModels from './models/recovery-request.model';
import * as SecurityQuestionModels from './models/security-question.model';
import * as TrustedContactModels from './models/trusted-contact.model';
import * as AuditLogModels from './models/audit-log.model';
import * as RiskAssessmentModels from './models/risk-assessment.model';

// Database connections
export {
  // Prisma
  connectDatabase,
  disconnectDatabase,
  isDatabaseConnected,
  checkPrismaHealth,

  // PostgreSQL
  connectPostgres,
  disconnectPostgres,
  getPostgresStatus,
  query,
  transaction,
  pool,

  // Redis
  connectRedis,
  disconnectRedis,
  getRedisStatus,
  isRedisConnected,
  redisCache,

  // Metrics
  MetricsCollector,

  // Query Builder
  createQueryBuilder,
  queryBuilder,
  QueryBuilder,
  QueryBuilderOptions,

  // Connection Wrapper
  ConnectionWrapper,
  db,

  // Connection Monitor
  ConnectionMonitor,
  connectionMonitor,
  HealthStatus,
  ConnectionMonitorOptions,

  // Database manager
  initializeDatabase,
  shutdownDatabase,
  getDatabaseHealth,
  isDbConnected,
};

// Repositories
export { repositories };

// Models
export {
  UserModels,
  CredentialModels,
  PasswordHistoryModels,
  SessionModels,
  MfaFactorModels,
  MfaChallengeModels,
  RecoveryTokenModels,
  RecoveryMethodModels,
  RecoveryRequestModels,
  SecurityQuestionModels,
  TrustedContactModels,
  AuditLogModels,
  RiskAssessmentModels,
};

/**
 * Initialize the data layer
 * This function should be called at application startup
 */
export async function initializeDataLayer(): Promise<void> {
  await initializeDatabase();
}

/**
 * Shutdown the data layer
 * This function should be called at application shutdown
 */
export async function shutdownDataLayer(): Promise<void> {
  await shutdownDatabase();
}

/**
 * Check the health of the data layer
 * @returns Object with status and details for each database connection
 */
export async function checkDataLayerHealth(): Promise<{
  status: string;
  prisma: { status: string; details?: string };
  postgres: { status: string; details?: string };
  redis: { status: string; details?: string };
}> {
  return await getDatabaseHealth();
}
