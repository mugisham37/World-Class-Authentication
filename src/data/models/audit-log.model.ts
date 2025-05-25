/**
 * Audit status enum
 * Represents the status of an audit log entry in the system
 */
export enum AuditStatus {
  SUCCESS = 'SUCCESS',
  FAILURE = 'FAILURE',
  WARNING = 'WARNING',
  INFO = 'INFO',
}

/**
 * Audit log model interface
 * Represents an audit log entry in the system
 */
export interface AuditLog {
  id: string;
  userId?: string | null;
  action: string;
  entityType?: string | null;
  entityId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, any> | null;
  createdAt: Date;
  status: AuditStatus;
}

/**
 * Create audit log data interface
 * Represents the data needed to create a new audit log entry
 */
export interface CreateAuditLogData {
  userId?: string;
  action: string;
  entityType?: string;
  entityId?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, any>;
  status?: AuditStatus;
}

/**
 * Audit log filter options interface
 * Represents the options for filtering audit logs
 */
export interface AuditLogFilterOptions {
  id?: string;
  userId?: string;
  action?: string;
  entityType?: string;
  entityId?: string;
  ipAddress?: string;
  status?: AuditStatus;
  createdAtBefore?: Date;
  createdAtAfter?: Date;
}
