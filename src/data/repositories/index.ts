import { UserRepository } from './user.repository';
import { SessionRepository } from './session.repository';
import { CredentialRepository } from './credential.repository';
import { PasswordHistoryRepository } from './password-history.repository';
import { MfaFactorRepository } from './mfa-factor.repository';
import { MfaChallengeRepository } from './mfa-challenge.repository';
import { RecoveryTokenRepository } from './recovery-token.repository';
import { RecoveryMethodRepository } from './recovery-method.repository';
import { SecurityQuestionRepository } from './security-question.repository';
import { TrustedContactRepository } from './trusted-contact.repository';
import { RecoveryRequestRepository } from './recovery-request.repository';
import { AdminApprovalRepository } from './admin-approval.repository';
import { AuditLogRepository } from './audit-log.repository';
import { RiskAssessmentRepository } from './risk-assessment.repository';
import { BaseRepository } from './base.repository';
import { TransactionManager } from './base.repository';
import { UserRepositoryImpl } from './implementations';

// Export repository interfaces
export {
  BaseRepository,
  TransactionManager,
  UserRepository,
  SessionRepository,
  CredentialRepository,
  PasswordHistoryRepository,
  MfaFactorRepository,
  MfaChallengeRepository,
  RecoveryTokenRepository,
  RecoveryMethodRepository,
  SecurityQuestionRepository,
  TrustedContactRepository,
  RecoveryRequestRepository,
  AdminApprovalRepository,
  AuditLogRepository,
  RiskAssessmentRepository,
};

// Export implementation classes
export * from './implementations';

// Create repository instances
export const userRepository = new UserRepositoryImpl();

// Export a repositories object for convenience
export const repositories = {
  user: userRepository,
};
