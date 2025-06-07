import { Router } from 'express';
import { complianceController } from '../controllers';
import { authenticate } from '../middlewares/auth.middleware';
import { validate } from '../middlewares/input-validation.middleware';
import { complianceValidators } from '../validators/compliance.validators';

/**
 * Compliance routes
 * Handles compliance-related operations such as GDPR requests
 */
const router = Router();

/**
 * @route POST /compliance/data-requests
 * @desc Submit a data subject request (DSR)
 * @access Public
 */
router.post(
  '/data-requests',
  validate(complianceValidators.submitDataRequest),
  complianceController.submitDataRequest
);

/**
 * @route GET /compliance/data-requests/:id
 * @desc Get data subject request status
 * @access Public
 */
router.get('/data-requests/:id', complianceController.getDataRequestStatus);

/**
 * @route GET /compliance/data-requests
 * @desc Get user's data subject requests
 * @access Private
 */
router.get('/data-requests', authenticate, complianceController.getUserDataRequests);

/**
 * @route DELETE /compliance/data-requests/:id
 * @desc Cancel a data subject request
 * @access Private
 */
router.delete('/data-requests/:id', authenticate, complianceController.cancelDataRequest);

/**
 * @route GET /compliance/policies/privacy
 * @desc Get privacy policy
 * @access Public
 */
router.get('/policies/privacy', complianceController.getPrivacyPolicy);

/**
 * @route GET /compliance/policies/terms
 * @desc Get terms of service
 * @access Public
 */
router.get('/policies/terms', complianceController.getTermsOfService);

/**
 * @route GET /compliance/policies/cookies
 * @desc Get cookie policy
 * @access Public
 */
router.get('/policies/cookies', complianceController.getCookiePolicy);

/**
 * @route PUT /compliance/cookie-preferences
 * @desc Update user cookie preferences
 * @access Public
 */
router.put(
  '/cookie-preferences',
  validate(complianceValidators.updateCookiePreferences),
  complianceController.updateCookiePreferences
);

/**
 * @route GET /compliance/data-processing
 * @desc Get data processing records
 * @access Private/Admin
 */
router.get('/data-processing', authenticate, complianceController.getDataProcessingRecords);

export const complianceRoutes = router;
