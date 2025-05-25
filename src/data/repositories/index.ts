import { userRepository, UserRepository } from './user.repository';
import { sessionRepository, SessionRepository } from './session.repository';
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
import { BaseRepository } from './base.repository';
import { TransactionManager } from './base.repository';

// Export repository interfaces
export {
  BaseRepository,
  TransactionManager,
  UserRepository,
  SessionRepository,
  RecoveryMethodRepository,
  SecurityQuestionRepository,
  TrustedContactRepository,
  RecoveryRequestRepository,
  AdminApprovalRepository,
};

// Export repository implementations
export {
  userRepository,
  sessionRepository,
  recoveryMethodRepository,
  securityQuestionRepository,
  trustedContactRepository,
  recoveryRequestRepository,
  adminApprovalRepository,
};

// Export a repositories object for convenience
export const repositories = {
  user: userRepository,
  session: sessionRepository,
  recoveryMethod: recoveryMethodRepository,
  securityQuestion: securityQuestionRepository,
  trustedContact: trustedContactRepository,
  recoveryRequest: recoveryRequestRepository,
  adminApproval: adminApprovalRepository,
};
