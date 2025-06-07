import { Router } from 'express';
import { trustedContactController } from '../controllers';
import { authenticate } from '../middlewares/auth.middleware';
import { validate } from '../middlewares/input-validation.middleware';
import { trustedContactValidators } from '../validators/trusted-contact.validators';

/**
 * Trusted Contact routes
 * Handles trusted contact management for account recovery
 */
const router = Router();

/**
 * @route GET /trusted-contacts
 * @desc Get trusted contacts for a user
 * @access Private
 */
router.get('/', authenticate, trustedContactController.getUserContacts);

/**
 * @route POST /trusted-contacts
 * @desc Add a trusted contact
 * @access Private
 */
router.post(
  '/',
  authenticate,
  validate(trustedContactValidators.addTrustedContact),
  trustedContactController.addTrustedContact
);

/**
 * @route DELETE /trusted-contacts/:contactId
 * @desc Remove a trusted contact
 * @access Private
 */
router.delete(
  '/:contactId',
  authenticate,
  validate(trustedContactValidators.removeTrustedContact, { source: 'params' }),
  trustedContactController.removeTrustedContact
);

/**
 * @route POST /trusted-contacts/register-recovery
 * @desc Register trusted contacts as a recovery method
 * @access Private
 */
router.post(
  '/register-recovery',
  authenticate,
  validate(trustedContactValidators.registerRecoveryMethod),
  trustedContactController.registerRecoveryMethod
);

/**
 * @route POST /trusted-contacts/initiate-recovery
 * @desc Initiate recovery using trusted contacts
 * @access Public
 */
router.post(
  '/initiate-recovery',
  validate(trustedContactValidators.initiateRecovery),
  trustedContactController.initiateRecovery
);

/**
 * @route POST /trusted-contacts/verify-recovery
 * @desc Verify recovery code from trusted contacts
 * @access Public
 */
router.post(
  '/verify-recovery',
  validate(trustedContactValidators.verifyRecovery),
  trustedContactController.verifyRecovery
);

/**
 * @route GET /trusted-contacts/availability/:userId
 * @desc Check if trusted contact recovery is available for a user
 * @access Public
 */
router.get(
  '/availability/:userId',
  validate(trustedContactValidators.checkAvailability, { source: 'params' }),
  trustedContactController.checkAvailability
);

export const trustedContactRoutes = router;
