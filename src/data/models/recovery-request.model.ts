import { RecoveryRequestType, RecoveryRequestStatus, AdminApprovalStatus } from '@prisma/client';

/**
 * Re-export Prisma's enums
 * Represents the types and statuses in the system
 */
export { RecoveryRequestType, RecoveryRequestStatus, AdminApprovalStatus };

/**
 * Recovery request model interface
 * Represents a recovery request in the system
 */
export interface RecoveryRequest {
  id: string;
  userId: string;
  type: RecoveryRequestType;
  status: RecoveryRequestStatus;
  initiatedAt: Date;
  completedAt?: Date | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, any> | null;
}

/**
 * Create recovery request data interface
 * Represents the data needed to create a new recovery request
 */
export interface CreateRecoveryRequestData {
  userId: string;
  type: RecoveryRequestType;
  status?: RecoveryRequestStatus;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, any>;
}

/**
 * Recovery request filter options interface
 * Represents the options for filtering recovery requests
 */
export interface RecoveryRequestFilterOptions {
  id?: string;
  userId?: string;
  type?: RecoveryRequestType;
  status?: RecoveryRequestStatus;
  initiatedAtBefore?: Date;
  initiatedAtAfter?: Date;
  completedAtBefore?: Date;
  completedAtAfter?: Date;
  ipAddress?: string;
}

/**
 * Recovery request with approvals interface
 * Represents a recovery request with its admin approvals
 */
export interface RecoveryRequestWithApprovals extends RecoveryRequest {
  adminApprovals: AdminApproval[];
}

/**
 * Admin approval model interface
 * Represents an admin approval for a recovery request
 */
export interface AdminApproval {
  id: string;
  recoveryRequestId: string;
  adminId: string;
  status: AdminApprovalStatus;
  notes?: string | null;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Create admin approval data interface
 * Represents the data needed to create a new admin approval
 */
export interface CreateAdminApprovalData {
  recoveryRequestId: string;
  adminId: string;
  status?: AdminApprovalStatus;
  notes?: string;
}

/**
 * Update admin approval data interface
 * Represents the data needed to update an existing admin approval
 */
export interface UpdateAdminApprovalData {
  status?: AdminApprovalStatus;
  notes?: string;
}
