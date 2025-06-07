import { Router } from 'express';
import { passwordlessController } from '../controllers';
import { authenticate } from '../middlewares/auth.middleware';
import { validate } from '../middlewares/input-validation.middleware';
import { passwordlessValidators } from '../validators/passwordless.validators';

/**
 * Passwordless authentication routes
 * Handles passwordless authentication methods like WebAuthn and magic links
 */
const router = Router();

/**
 * @route POST /passwordless/authenticate/start
 * @desc Start passwordless authentication flow
 * @access Public
 */
router.post(
  '/authenticate/start',
  validate(passwordlessValidators.startAuthentication),
  passwordlessController.startAuthentication
);

/**
 * @route POST /passwordless/authenticate/complete
 * @desc Complete passwordless authentication flow
 * @access Public
 */
router.post(
  '/authenticate/complete',
  validate(passwordlessValidators.completeAuthentication),
  passwordlessController.completeAuthentication
);

/**
 * @route POST /passwordless/register/start
 * @desc Start passwordless credential registration
 * @access Private
 */
router.post(
  '/register/start',
  authenticate,
  validate(passwordlessValidators.startRegistration),
  passwordlessController.startRegistration
);

/**
 * @route POST /passwordless/register/complete
 * @desc Complete passwordless credential registration
 * @access Private
 */
router.post(
  '/register/complete',
  authenticate,
  validate(passwordlessValidators.completeRegistration),
  passwordlessController.completeRegistration
);

/**
 * @route GET /passwordless/credentials
 * @desc Get passwordless credentials for a user
 * @access Private
 */
router.get('/credentials', authenticate, passwordlessController.getCredentials);

/**
 * @route DELETE /passwordless/credentials/:credentialId
 * @desc Delete a passwordless credential
 * @access Private
 */
router.delete(
  '/credentials/:credentialId',
  authenticate,
  validate(passwordlessValidators.deleteCredential, { source: 'params' }),
  passwordlessController.deleteCredential
);

export const passwordlessRoutes = router;
