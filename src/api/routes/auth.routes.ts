import { Router } from 'express';
import { authController } from '../controllers';
import { authenticate } from '../middlewares/auth.middleware';
import { validate } from '../middlewares/input-validation.middleware';
import { authValidators } from '../validators/auth.validators';
import { authRateLimiter } from '../middlewares/rate-limiting.middleware';

/**
 * Authentication routes
 * Handles user authentication, registration, and session management
 */
const router = Router();

/**
 * @route POST /auth/register
 * @desc Register a new user
 * @access Public
 */
router.post(
  '/register',
  authRateLimiter,
  validate(authValidators.register),
  authController.register
);

/**
 * @route POST /auth/login
 * @desc Authenticate a user
 * @access Public
 */
router.post('/login', authRateLimiter, validate(authValidators.login), authController.login);

/**
 * @route POST /auth/logout
 * @desc Logout a user
 * @access Private
 */
router.post('/logout', authenticate, authController.logout);

/**
 * @route POST /auth/logout-all
 * @desc Logout from all sessions
 * @access Private
 */
router.post('/logout-all', authenticate, authController.logoutAll);

/**
 * @route GET /auth/verify
 * @desc Verify a user's token
 * @access Private
 */
router.get('/verify', authenticate, authController.verifyToken);

/**
 * @route POST /auth/refresh
 * @desc Refresh a user's token
 * @access Public
 */
router.post('/refresh', validate(authValidators.refreshToken), authController.refreshToken);

/**
 * @route POST /auth/verify-email
 * @desc Verify email with token
 * @access Public
 */
router.post('/verify-email', validate(authValidators.verifyEmail), authController.verifyEmail);

/**
 * @route POST /auth/resend-verification
 * @desc Resend verification email
 * @access Private
 */
router.post('/resend-verification', authenticate, authController.resendVerification);

/**
 * @route POST /auth/forgot-password
 * @desc Request password reset
 * @access Public
 */
router.post(
  '/forgot-password',
  authRateLimiter,
  validate(authValidators.forgotPassword),
  authController.forgotPassword
);

/**
 * @route POST /auth/reset-password
 * @desc Reset password with token
 * @access Public
 */
router.post(
  '/reset-password',
  authRateLimiter,
  validate(authValidators.resetPassword),
  authController.resetPassword
);

/**
 * @route POST /auth/change-password
 * @desc Change password
 * @access Private
 */
router.post(
  '/change-password',
  authenticate,
  validate(authValidators.changePassword),
  authController.changePassword
);

/**
 * @route GET /auth/sessions
 * @desc Get user sessions
 * @access Private
 */
router.get('/sessions', authenticate, authController.getSessions);

/**
 * @route DELETE /auth/sessions/:id
 * @desc Terminate a session
 * @access Private
 */
router.delete('/sessions/:id', authenticate, authController.terminateSession);

/**
 * @route GET /auth/me
 * @desc Get current user profile
 * @access Private
 */
router.get('/me', authenticate, authController.getCurrentUser);

/**
 * @route PUT /auth/me
 * @desc Update current user profile
 * @access Private
 */
router.put(
  '/me',
  authenticate,
  validate(authValidators.updateProfile),
  authController.updateCurrentUser
);

export const authRoutes = router;
