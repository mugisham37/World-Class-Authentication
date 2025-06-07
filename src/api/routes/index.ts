import { Router } from 'express';
import { authRoutes } from './auth.routes';
import { mfaRoutes } from './mfa.routes';
import { recoveryRoutes } from './recovery.routes';
import { healthRoutes } from './health.routes';
import { auditRoutes } from './audit.routes';
import { complianceRoutes } from './compliance.routes';
import { oauthRoutes } from './oauth.routes';
import { passwordlessRoutes } from './passwordless.routes';
import { performanceRoutes } from './performance.routes';
import { riskRoutes } from './risk.routes';
import { securityQuestionsRoutes } from './security-questions.routes';
import { ssoRoutes } from './sso.routes';
import { trustedContactRoutes } from './trusted-contact.routes';
import { userRoutes } from './user.routes';
import { errorMiddleware } from '../middlewares';

/**
 * Main API router
 * Combines all route modules into a single router
 */
const router = Router();

// Health routes - Keep at the top for quick health checks
router.use('/health', healthRoutes);

// Core authentication routes
router.use('/auth', authRoutes);
router.use('/mfa', mfaRoutes);
router.use('/recovery', recoveryRoutes);

// User management routes
router.use('/users', userRoutes);

// Security and compliance routes
router.use('/audit', auditRoutes);
router.use('/compliance', complianceRoutes);
router.use('/risk', riskRoutes);

// Advanced authentication routes
router.use('/oauth', oauthRoutes);
router.use('/passwordless', passwordlessRoutes);
router.use('/sso', ssoRoutes);

// Supporting routes
router.use('/performance', performanceRoutes);
router.use('/security-questions', securityQuestionsRoutes);
router.use('/trusted-contacts', trustedContactRoutes);

// Apply error handling middleware
router.use(errorMiddleware);

export { router as apiRouter };
