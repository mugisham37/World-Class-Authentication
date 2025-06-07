import { Router } from 'express';
import { mfaController } from '../controllers';
import { authenticate } from '../middlewares/auth.middleware';
import { validate } from '../middlewares/input-validation.middleware';
import { mfaValidators } from '../validators/mfa.validators';
import { authRateLimiter } from '../middlewares/rate-limiting.middleware';

/**
 * Multi-Factor Authentication routes
 * Handles MFA setup, verification, and management
 */
const router = Router();

/**
 * @route GET /mfa/factors
 * @desc Get all MFA factors for the authenticated user
 * @access Private
 */
router.get('/factors', authenticate, mfaController.getUserFactors);

/**
 * @route POST /mfa/factors
 * @desc Start enrollment for a new MFA factor
 * @access Private
 */
router.post(
  '/factors',
  authenticate,
  validate(mfaValidators.startFactorEnrollment),
  mfaController.startFactorEnrollment
);

/**
 * @route POST /mfa/factors/:factorId/verify
 * @desc Complete enrollment by verifying a new MFA factor
 * @access Private
 */
router.post(
  '/factors/:factorId/verify',
  authenticate,
  validate(mfaValidators.verifyFactorEnrollment),
  mfaController.verifyFactorEnrollment
);

/**
 * @route POST /mfa/challenge
 * @desc Generate an MFA challenge for a specific factor
 * @access Public (but protected by challenge)
 */
router.post(
  '/challenge',
  authRateLimiter,
  validate(mfaValidators.generateChallenge),
  mfaController.generateChallenge
);

/**
 * @route POST /mfa/challenge/:challengeId/verify
 * @desc Verify an MFA challenge response
 * @access Public (but protected by challenge)
 */
router.post(
  '/challenge/:challengeId/verify',
  authRateLimiter,
  validate(mfaValidators.verifyChallenge),
  mfaController.verifyChallenge
);

/**
 * @route PUT /mfa/factors/:factorId/disable
 * @desc Disable an MFA factor
 * @access Private
 */
router.put('/factors/:factorId/disable', authenticate, mfaController.disableFactor);

/**
 * @route PUT /mfa/factors/:factorId/enable
 * @desc Enable a previously disabled MFA factor
 * @access Private
 */
router.put('/factors/:factorId/enable', authenticate, mfaController.enableFactor);

/**
 * @route DELETE /mfa/factors/:factorId
 * @desc Delete an MFA factor
 * @access Private
 */
router.delete('/factors/:factorId', authenticate, mfaController.deleteFactor);

/**
 * @route POST /mfa/recovery-codes/regenerate
 * @desc Regenerate recovery codes
 * @access Private
 */
router.post('/recovery-codes/regenerate', authenticate, mfaController.regenerateRecoveryCodes);

/**
 * @route GET /mfa/recovery-codes
 * @desc Get recovery codes
 * @access Private
 */
router.get('/recovery-codes', authenticate, mfaController.getRecoveryCodes);

/**
 * @route POST /mfa/recovery-codes/verify
 * @desc Verify a recovery code
 * @access Public
 */
router.post(
  '/recovery-codes/verify',
  authRateLimiter,
  validate(mfaValidators.verifyRecoveryCode),
  mfaController.verifyRecoveryCode
);

export const mfaRoutes = router;
