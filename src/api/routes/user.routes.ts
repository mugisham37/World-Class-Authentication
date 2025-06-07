import { Router } from 'express';
import { userController } from '../controllers';
import { authenticate } from '../middlewares/auth.middleware';
import { validate } from '../middlewares/input-validation.middleware';
import { userValidators } from '../validators/user.validators';

/**
 * User routes
 * Handles user profile management and settings
 */
const router = Router();

/**
 * @route GET /users/me
 * @desc Get current user profile
 * @access Private
 */
router.get('/me', authenticate, userController.getCurrentUser);

/**
 * @route PUT /users/me
 * @desc Update current user profile
 * @access Private
 */
router.put(
  '/me',
  authenticate,
  validate(userValidators.updateCurrentUser),
  userController.updateCurrentUser
);

/**
 * @route PUT /users/me/email
 * @desc Update user email
 * @access Private
 */
router.put(
  '/me/email',
  authenticate,
  validate(userValidators.updateEmail),
  userController.updateEmail
);

/**
 * @route PUT /users/me/phone
 * @desc Update user phone number
 * @access Private
 */
router.put(
  '/me/phone',
  authenticate,
  validate(userValidators.updatePhoneNumber),
  userController.updatePhoneNumber
);

/**
 * @route POST /users/me/phone/verify
 * @desc Verify phone number with code
 * @access Private
 */
router.post(
  '/me/phone/verify',
  authenticate,
  validate(userValidators.verifyPhoneNumber),
  userController.verifyPhoneNumber
);

/**
 * @route PUT /users/me/preferences
 * @desc Update user preferences
 * @access Private
 */
router.put(
  '/me/preferences',
  authenticate,
  validate(userValidators.updatePreferences),
  userController.updatePreferences
);

/**
 * @route GET /users/me/activity
 * @desc Get user activity log
 * @access Private
 */
router.get(
  '/me/activity',
  authenticate,
  validate(userValidators.getActivityLog, { source: 'query' }),
  userController.getActivityLog
);

/**
 * @route POST /users/me/delete
 * @desc Request account deletion
 * @access Private
 */
router.post(
  '/me/delete',
  authenticate,
  validate(userValidators.requestAccountDeletion),
  userController.requestAccountDeletion
);

/**
 * @route POST /users/me/delete/cancel
 * @desc Cancel account deletion request
 * @access Private
 */
router.post(
  '/me/delete/cancel',
  authenticate,
  validate(userValidators.cancelAccountDeletion),
  userController.cancelAccountDeletion
);

/**
 * @route GET /users/me/export
 * @desc Export user data
 * @access Private
 */
router.get(
  '/me/export',
  authenticate,
  validate(userValidators.exportUserData, { source: 'query' }),
  userController.exportUserData
);

export const userRoutes = router;
