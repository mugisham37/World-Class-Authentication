import { Router } from 'express';
import { securityQuestionsController } from '../controllers';
import { authenticate } from '../middlewares/auth.middleware';
import { validate } from '../middlewares/input-validation.middleware';
import { securityQuestionsValidators } from '../validators/security-questions.validators';

/**
 * Security Questions routes
 * Handles security questions setup and management for account recovery
 */
const router = Router();

/**
 * @route GET /security-questions
 * @desc Get security questions for a user
 * @access Private
 */
router.get('/', authenticate, securityQuestionsController.getUserQuestions);

/**
 * @route POST /security-questions
 * @desc Set up security questions for a user
 * @access Private
 */
router.post(
  '/',
  authenticate,
  validate(securityQuestionsValidators.setupSecurityQuestions),
  securityQuestionsController.setupSecurityQuestions
);

/**
 * @route PUT /security-questions
 * @desc Update security questions for a user
 * @access Private
 */
router.put(
  '/',
  authenticate,
  validate(securityQuestionsValidators.updateSecurityQuestions),
  securityQuestionsController.updateSecurityQuestions
);

/**
 * @route POST /security-questions/verify
 * @desc Verify security questions for a user
 * @access Public
 */
router.post(
  '/verify',
  validate(securityQuestionsValidators.verifySecurityQuestions),
  securityQuestionsController.verifySecurityQuestions
);

export const securityQuestionsRoutes = router;
