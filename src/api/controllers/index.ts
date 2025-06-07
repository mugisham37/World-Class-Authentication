import { authController } from './auth.controller';
import { mfaController } from './mfa.controller';
import { recoveryController } from './recovery.controller';
import { healthController } from './health.controller';
import { auditController } from './audit.controller';
import { complianceController } from './compliance.controller';
import { riskController } from './risk.controller';
import { performanceController } from './performance.controller';
import { oauthController } from './oauth.controller';
import { passwordlessController } from './passwordless.controller';
import { securityQuestionsController } from './security-questions.controller';
import { ssoController } from './sso.controller';
import { trustedContactController } from './trusted-contact.controller';
import { userController } from './user.controller';

/**
 * Export all controllers
 * This makes it easier to import controllers in route files
 */
export {
  authController,
  mfaController,
  recoveryController,
  healthController,
  auditController,
  complianceController,
  riskController,
  performanceController,
  oauthController,
  passwordlessController,
  securityQuestionsController,
  ssoController,
  trustedContactController,
  userController,
};

/**
 * Export BaseController for extension
 */
export { BaseController } from './base.controller';
