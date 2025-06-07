/**
 * Validators Index
 * Exports all validators for easy importing throughout the application
 */

import { authValidators } from './auth.validators';
import { mfaValidators } from './mfa.validators';
import { recoveryValidators } from './recovery.validators';
import { auditValidators } from './audit.validators';
import { complianceValidators } from './compliance.validators';
import { oauthValidators } from './oauth.validators';
import { passwordlessValidators } from './passwordless.validators';
import { performanceValidators } from './performance.validators';
import { riskValidators } from './risk.validators';
import { securityQuestionsValidators } from './security-questions.validators';
import { ssoValidators } from './sso.validators';
import { trustedContactValidators } from './trusted-contact.validators';
import { userValidators } from './user.validators';

export {
  authValidators,
  mfaValidators,
  recoveryValidators,
  auditValidators,
  complianceValidators,
  oauthValidators,
  passwordlessValidators,
  performanceValidators,
  riskValidators,
  securityQuestionsValidators,
  ssoValidators,
  trustedContactValidators,
  userValidators,
};

// Export interfaces for context-aware validation
export type { AuthValidationContext } from './auth.validators';

export type { MfaValidationContext } from './mfa.validators';

export type { RecoveryValidationContext } from './recovery.validators';

export type { AuditValidationContext } from './audit.validators';

export type { ComplianceValidationContext } from './compliance.validators';

export type { OAuthValidationContext } from './oauth.validators';

export type { PasswordlessValidationContext } from './passwordless.validators';

export type { PerformanceValidationContext } from './performance.validators';

export type { RiskValidationContext } from './risk.validators';

export type { SecurityQuestionsValidationContext } from './security-questions.validators';

export type { SSOValidationContext } from './sso.validators';

export type { TrustedContactValidationContext } from './trusted-contact.validators';

export type { UserValidationContext } from './user.validators';
