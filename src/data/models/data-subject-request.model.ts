import { DataSubjectRequestStatus, DataSubjectRequestType } from '@prisma/client';

/**
 * Data Subject Request input interface
 */
export interface DataSubjectRequestCreateInput {
  id?: string;
  type: DataSubjectRequestType;
  status: DataSubjectRequestStatus;
  email: string;
  firstName?: string | null;
  lastName?: string | null;
  userId?: string | null;
  requestReason?: string | null;
  additionalInfo?: Record<string, any> | null;
  requestedBy?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  verificationToken?: string | null;
  expiresAt?: Date | null;
  createdAt?: Date;
  updatedAt?: Date;
}

/**
 * Data Subject Request update interface
 */
export interface DataSubjectRequestUpdateInput {
  type?: DataSubjectRequestType | undefined;
  status?: DataSubjectRequestStatus | undefined;
  email?: string | undefined;
  firstName?: string | null | undefined;
  lastName?: string | null | undefined;
  userId?: string | null | undefined;
  requestReason?: string | null | undefined;
  additionalInfo?: Record<string, any> | null | undefined;
  requestedBy?: string | null | undefined;
  ipAddress?: string | null | undefined;
  userAgent?: string | null | undefined;
  verificationToken?: string | null | undefined;
  expiresAt?: Date | null | undefined;
  verifiedAt?: Date | null | undefined;
  processingStartedAt?: Date | null | undefined;
  completedAt?: Date | null | undefined;
  result?: Record<string, any> | null | undefined;
  updatedAt?: Date | undefined;
}

/**
 * Data Subject Request search options interface
 */
export interface DataSubjectRequestSearchOptions {
  skip?: number;
  limit?: number;
  type?: DataSubjectRequestType;
  status?: DataSubjectRequestStatus;
  startDate?: Date;
  endDate?: Date;
  query?: string;
}

/**
 * Data Subject Request statistics options interface
 */
export interface DataSubjectRequestStatisticsOptions {
  startDate?: Date;
  endDate?: Date;
  groupBy?: 'type' | 'status' | 'day' | 'week' | 'month';
}

/**
 * Data Subject Request timeline options interface
 */
export interface DataSubjectRequestTimelineOptions {
  startDate?: Date;
  endDate?: Date;
  interval?: 'day' | 'week' | 'month';
}
