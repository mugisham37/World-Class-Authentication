/**
 * Recovery context interface
 * Represents the context for recovery operations
 */
export interface RecoveryContext {
  ipAddress?: string;
  userAgent?: string;
  [key: string]: any;
}
