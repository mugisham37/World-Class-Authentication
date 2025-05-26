/**
 * Risk level enum
 * Represents the risk level of an assessment in the system
 */
export enum RiskLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

/**
 * Risk assessment model interface
 * Represents a risk assessment in the system
 */
export interface RiskAssessment {
  id: string;
  userId?: string | null;
  sessionId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  deviceId?: string | null;
  location?: string | null;
  riskLevel: RiskLevel;
  riskFactors: Record<string, any>;
  riskScore?: number;
  action?: string;
  createdAt: Date;
  updatedAt: Date;
  resolvedAt?: Date | null;
  resolution?: string | null;
}

/**
 * Create risk assessment data interface
 * Represents the data needed to create a new risk assessment
 */
export interface CreateRiskAssessmentData {
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
  deviceId?: string;
  location?: string;
  riskLevel: RiskLevel;
  riskFactors: Record<string, any>;
  riskScore?: number;
  action?: string;
}

/**
 * Update risk assessment data interface
 * Represents the data needed to update an existing risk assessment
 */
export interface UpdateRiskAssessmentData {
  riskLevel?: RiskLevel;
  riskFactors?: Record<string, any>;
  riskScore?: number;
  action?: string;
  resolvedAt?: Date;
  resolution?: string;
}

/**
 * Risk assessment filter options interface
 * Represents the options for filtering risk assessments
 */
export interface RiskAssessmentFilterOptions {
  id?: string;
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  deviceId?: string;
  riskLevel?: RiskLevel;
  isResolved?: boolean;
  createdAtBefore?: Date;
  createdAtAfter?: Date;
  updatedAtBefore?: Date;
  updatedAtAfter?: Date;
  resolvedAtBefore?: Date;
  resolvedAtAfter?: Date;
  limit?: number;
  offset?: number;
}
