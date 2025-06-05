/**
 * Audit status enum
 * Represents the status of an audit log entry
 */
export enum AuditStatus {
  INFO = "INFO",
  SUCCESS = "SUCCESS",
  FAILURE = "FAILURE",
  WARNING = "WARNING"
}

/**
 * Audit severity enum
 * Represents the severity level of an audit log entry
 */
export enum AuditSeverity {
  INFO = "info",
  WARNING = "warning",
  ERROR = "error",
  CRITICAL = "critical"
}

/**
 * Audit log interface
 * Represents an audit log entry in the system
 */
export interface AuditLog {
  id: string;
  userId: string | null;
  action: string;
  entityType: string | null;
  entityId: string | null;
  metadata: Record<string, any>;
  ipAddress: string | null;
  userAgent: string | null;
  status: AuditStatus;
  severity: AuditSeverity;
  createdAt: Date;
}

/**
 * Audit error class
 * Custom error class for audit-related errors
 */
export class AuditLogError extends Error {
  constructor(message: string, public override readonly cause?: unknown) {
    super(message);
    this.name = 'AuditLogError';
  }
}

/**
 * Handle audit error utility function
 * @param error The error to handle
 * @param context The context in which the error occurred
 */
export function handleAuditError(error: unknown, context: string): never {
  if (error instanceof Error) {
    throw new AuditLogError(`${context}: ${error.message}`, error);
  }
  throw new AuditLogError(`${context}: ${String(error)}`);
}
