/**
 * Event handler function type
 */
export type EventHandler<T> = (payload: T) => void | Promise<void>;

/**
 * Event types enum
 */
export enum EventType {
  // User events
  USER_REGISTERED = 'user.registered',
  USER_UPDATED = 'user.updated',
  USER_DELETED = 'user.deleted',

  // Authentication events
  AUTH_LOGIN_ATTEMPT = 'auth.login.attempt',
  AUTH_LOGIN_SUCCESS = 'auth.login.success',
  AUTH_LOGIN_FAILURE = 'auth.login.failure',
  AUTH_LOGOUT = 'auth.logout',

  // MFA events
  MFA_FACTOR_REGISTERED = 'mfa.factor.registered',
  MFA_FACTOR_REMOVED = 'mfa.factor.removed',
  MFA_CHALLENGE_ISSUED = 'mfa.challenge.issued',
  MFA_CHALLENGE_VERIFIED = 'mfa.challenge.verified',
  MFA_CHALLENGE_FAILED = 'mfa.challenge.failed',

  // Session events
  SESSION_CREATED = 'session.created',
  SESSION_UPDATED = 'session.updated',
  SESSION_EXPIRED = 'session.expired',
  SESSION_TERMINATED = 'session.terminated',

  // Risk events
  RISK_ASSESSMENT_COMPLETED = 'risk.assessment.completed',
  RISK_LEVEL_CHANGED = 'risk.level.changed',
  RISK_ANOMALY_DETECTED = 'risk.anomaly.detected',

  // Recovery events
  RECOVERY_INITIATED = 'recovery.initiated',
  RECOVERY_COMPLETED = 'recovery.completed',
  RECOVERY_FAILED = 'recovery.failed',

  // Audit events
  AUDIT_SECURITY_EVENT = 'audit.security.event',
  AUDIT_ADMIN_ACTION = 'audit.admin.action',
  AUDIT_DATA_ACCESS = 'audit.data.access',

  // System events
  SYSTEM_ERROR = 'system.error',
  SYSTEM_WARNING = 'system.warning',
  SYSTEM_INFO = 'system.info',
}

/**
 * Base event payload interface
 * All event payloads should extend this interface
 */
export interface BaseEventPayload {
  timestamp: Date;
  correlationId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * User registered event payload
 */
export interface UserRegisteredPayload extends BaseEventPayload {
  userId: string;
  email: string;
  username?: string;
}

/**
 * User updated event payload
 */
export interface UserUpdatedPayload extends BaseEventPayload {
  userId: string;
  updatedFields: string[];
  previousValues?: Record<string, unknown>;
  newValues?: Record<string, unknown>;
}

/**
 * User deleted event payload
 */
export interface UserDeletedPayload extends BaseEventPayload {
  userId: string;
  email: string;
  reason?: string;
}

/**
 * Authentication login attempt payload
 */
export interface AuthLoginAttemptPayload extends BaseEventPayload {
  userId?: string;
  email: string;
  ipAddress: string;
  userAgent: string;
  geoLocation?: {
    country?: string;
    region?: string;
    city?: string;
  };
}

/**
 * Authentication login success payload
 */
export interface AuthLoginSuccessPayload extends BaseEventPayload {
  userId: string;
  email: string;
  ipAddress: string;
  userAgent: string;
  sessionId: string;
  mfaUsed: boolean;
  geoLocation?: {
    country?: string;
    region?: string;
    city?: string;
  };
}

/**
 * Authentication login failure payload
 */
export interface AuthLoginFailurePayload extends BaseEventPayload {
  userId?: string;
  email: string;
  ipAddress: string;
  userAgent: string;
  reason: string;
  geoLocation?: {
    country?: string;
    region?: string;
    city?: string;
  };
  attemptCount: number;
}

/**
 * Authentication logout payload
 */
export interface AuthLogoutPayload extends BaseEventPayload {
  userId: string;
  sessionId: string;
  ipAddress: string;
  userAgent: string;
  reason?: 'user_initiated' | 'session_expired' | 'admin_action' | 'security_policy';
}

/**
 * MFA factor registered payload
 */
export interface MfaFactorRegisteredPayload extends BaseEventPayload {
  userId: string;
  factorId: string;
  factorType: string;
  ipAddress: string;
  userAgent: string;
}

/**
 * MFA challenge issued payload
 */
export interface MfaChallengeIssuedPayload extends BaseEventPayload {
  userId: string;
  challengeId: string;
  factorType: string;
  ipAddress: string;
  userAgent: string;
  sessionId?: string;
}

/**
 * MFA challenge verified payload
 */
export interface MfaChallengeVerifiedPayload extends BaseEventPayload {
  userId: string;
  challengeId: string;
  factorType: string;
  ipAddress: string;
  userAgent: string;
  sessionId?: string;
  verificationLatency: number; // milliseconds
}

/**
 * Risk assessment completed payload
 */
export interface RiskAssessmentCompletedPayload extends BaseEventPayload {
  userId: string;
  sessionId: string;
  requestId: string;
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  factors: Record<string, number>;
  action: 'allow' | 'challenge' | 'block';
}

/**
 * Risk level changed payload
 */
export interface RiskLevelChangedPayload extends BaseEventPayload {
  userId: string;
  previousLevel: 'low' | 'medium' | 'high' | 'critical';
  newLevel: 'low' | 'medium' | 'high' | 'critical';
  reason: string;
  triggeredBy: 'automatic' | 'manual' | 'policy';
}

/**
 * Audit security event payload
 */
export interface AuditSecurityEventPayload extends BaseEventPayload {
  eventType: string;
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
  resourceType?: string;
  resourceId?: string;
  action: string;
  outcome: 'success' | 'failure';
  details?: Record<string, unknown>;
}

/**
 * System error event payload
 */
export interface SystemErrorPayload extends BaseEventPayload {
  errorCode: string;
  errorMessage: string;
  stackTrace?: string;
  component: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  affectedUsers?: string[];
}
