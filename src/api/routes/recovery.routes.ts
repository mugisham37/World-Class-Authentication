import { Router } from 'express';
import {
  recoveryController,
  securityQuestionsController,
  trustedContactController,
} from '../controllers';
import { authenticate } from '../middlewares/auth.middleware';
import { validate } from '../middlewares/input-validation.middleware';
import { recoveryValidators } from '../validators/recovery.validators';
import { authRateLimiter } from '../middlewares/rate-limiting.middleware';

/**
 * Recovery routes
 * Handles account recovery and password reset operations
 */
const router = Router();

/**
 * @route GET /recovery/methods
 * @desc Get all recovery methods for the authenticated user
 * @access Private
 */
router.get('/methods', authenticate, recoveryController.getUserRecoveryMethods);

/**
 * @route GET /recovery/methods/available
 * @desc Get available recovery methods for the authenticated user
 * @access Private
 */
router.get('/methods/available', authenticate, recoveryController.getAvailableRecoveryMethods);

/**
 * @route POST /recovery/methods
 * @desc Register a new recovery method
 * @access Private
 */
router.post(
  '/methods',
  authenticate,
  validate(recoveryValidators.registerRecoveryMethod),
  recoveryController.registerRecoveryMethod
);

/**
 * @route PUT /recovery/methods/:methodId/disable
 * @desc Disable a recovery method
 * @access Private
 */
router.put('/methods/:methodId/disable', authenticate, recoveryController.disableRecoveryMethod);

/**
 * @route PUT /recovery/methods/:methodId/enable
 * @desc Enable a previously disabled recovery method
 * @access Private
 */
router.put('/methods/:methodId/enable', authenticate, recoveryController.enableRecoveryMethod);

/**
 * @route POST /recovery/initiate
 * @desc Initiate account recovery process
 * @access Public
 */
router.post(
  '/initiate',
  authRateLimiter,
  validate(recoveryValidators.initiateRecovery),
  recoveryController.initiateRecovery
);

/**
 * @route POST /recovery/verify
 * @desc Verify recovery challenge
 * @access Public
 */
router.post(
  '/verify',
  authRateLimiter,
  validate(recoveryValidators.verifyRecoveryChallenge),
  recoveryController.verifyRecoveryChallenge
);

/**
 * @route POST /recovery/complete
 * @desc Complete account recovery process
 * @access Public
 */
router.post(
  '/complete',
  authRateLimiter,
  validate(recoveryValidators.completeRecovery),
  recoveryController.completeRecovery
);

/**
 * @route PUT /recovery/requests/:requestId/cancel
 * @desc Cancel a recovery request
 * @access Private
 */
router.put('/requests/:requestId/cancel', authenticate, recoveryController.cancelRecoveryRequest);

/**
 * Security Questions Routes
 */

/**
 * @route GET /recovery/security-questions
 * @desc Get security questions for a user
 * @access Private
 */
router.get('/security-questions', authenticate, securityQuestionsController.getUserQuestions);

/**
 * @route POST /recovery/security-questions
 * @desc Set security questions for a user
 * @access Private
 */
router.post(
  '/security-questions',
  authenticate,
  validate(recoveryValidators.setSecurityQuestions),
  securityQuestionsController.setupSecurityQuestions
);

/**
 * Trusted Contacts Routes
 */

/**
 * @route GET /recovery/trusted-contacts
 * @desc Get trusted contacts for a user
 * @access Private
 */
router.get('/trusted-contacts', authenticate, trustedContactController.getUserContacts);

/**
 * @route POST /recovery/trusted-contacts
 * @desc Add a trusted contact
 * @access Private
 */
router.post(
  '/trusted-contacts',
  authenticate,
  validate(recoveryValidators.addTrustedContact),
  trustedContactController.addTrustedContact
);

/**
 * @route DELETE /recovery/trusted-contacts/:contactId
 * @desc Remove a trusted contact
 * @access Private
 */
router.delete(
  '/trusted-contacts/:contactId',
  authenticate,
  trustedContactController.removeTrustedContact
);

export const recoveryRoutes = router;
