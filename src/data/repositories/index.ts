import { userRepository, UserRepository } from './user.repository';
import { sessionRepository, SessionRepository } from './session.repository';
import { credentialRepository, CredentialRepository } from './credential.repository';
import {
  passwordHistoryRepository,
  PasswordHistoryRepository,
} from './password-history.repository';
import { mfaFactorRepository, MfaFactorRepository } from './mfa-factor.repository';
import { mfaChallengeRepository, MfaChallengeRepository } from './mfa-challenge.repository';
import { recoveryTokenRepository, RecoveryTokenRepository } from './recovery-token.repository';
import { recoveryMethodRepository, RecoveryMethodRepository } from './recovery-method.repository';
import {
  securityQuestionRepository,
  SecurityQuestionRepository,
} from './security-question.repository';
import { trustedContactRepository, TrustedContactRepository } from './trusted-contact.repository';
import {
  recoveryRequestRepository,
  RecoveryRequestRepository,
} from './recovery-request.repository';
import { adminApprovalRepository, AdminApprovalRepository } from './admin-approval.repository';
import { auditLogRepository, AuditLogRepository } from './audit-log.repository';
import { riskAssessmentRepository, RiskAssessmentRepository } from './risk-assessment.repository';
import { BaseRepository } from './base.repository';
import { TransactionManager } from './base.repository';

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

// Export repository implementations
export {
  userRepository,
  sessionRepository,
  credentialRepository,
  passwordHistoryRepository,
  mfaFactorRepository,
  mfaChallengeRepository,
  recoveryTokenRepository,
  recoveryMethodRepository,
  securityQuestionRepository,
  trustedContactRepository,
  recoveryRequestRepository,
  adminApprovalRepository,
  auditLogRepository,
  riskAssessmentRepository,
};

// Export a repositories object for convenience
export const repositories = {
  user: userRepository,
  session: sessionRepository,
  credential: credentialRepository,
  passwordHistory: passwordHistoryRepository,
  mfaFactor: mfaFactorRepository,
  mfaChallenge: mfaChallengeRepository,
  recoveryToken: recoveryTokenRepository,
  recoveryMethod: recoveryMethodRepository,
  securityQuestion: securityQuestionRepository,
  trustedContact: trustedContactRepository,
  recoveryRequest: recoveryRequestRepository,
  adminApproval: adminApprovalRepository,
  auditLog: auditLogRepository,
  riskAssessment: riskAssessmentRepository,
};
