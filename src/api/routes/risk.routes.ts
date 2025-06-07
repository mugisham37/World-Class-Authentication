import { Router } from 'express';
import { riskController } from '../controllers';
import { authenticate } from '../middlewares/auth.middleware';
import { validate } from '../middlewares/input-validation.middleware';
import { riskValidators } from '../validators/risk.validators';

/**
 * Risk routes
 * Handles risk assessment and fraud prevention operations
 */
const router = Router();

/**
 * @route GET /risk/assessment
 * @desc Get risk assessment for current user
 * @access Private
 */
router.get(
  '/assessment',
  authenticate,
  validate(riskValidators.getRiskAssessment, { source: 'query' }),
  riskController.getRiskAssessment
);

/**
 * @route GET /risk/suspicious-activities
 * @desc Get suspicious activities
 * @access Private
 */
router.get(
  '/suspicious-activities',
  authenticate,
  validate(riskValidators.getSuspiciousActivities, { source: 'query' }),
  riskController.getSuspiciousActivities
);

/**
 * @route PUT /risk/suspicious-activities/:id/resolve
 * @desc Mark suspicious activity as resolved
 * @access Private
 */
router.put(
  '/suspicious-activities/:id/resolve',
  authenticate,
  validate(riskValidators.resolveSuspiciousActivity),
  riskController.resolveSuspiciousActivity
);

/**
 * @route GET /risk/trusted-devices
 * @desc Get trusted devices
 * @access Private
 */
router.get(
  '/trusted-devices',
  authenticate,
  validate(riskValidators.getTrustedDevices, { source: 'query' }),
  riskController.getTrustedDevices
);

/**
 * @route DELETE /risk/trusted-devices/:id
 * @desc Remove trusted device
 * @access Private
 */
router.delete(
  '/trusted-devices/:id',
  authenticate,
  validate(riskValidators.removeTrustedDevice, { source: 'params' }),
  riskController.removeTrustedDevice
);

/**
 * @route GET /risk/trusted-locations
 * @desc Get trusted locations
 * @access Private
 */
router.get(
  '/trusted-locations',
  authenticate,
  validate(riskValidators.getTrustedLocations, { source: 'query' }),
  riskController.getTrustedLocations
);

/**
 * @route POST /risk/trusted-locations
 * @desc Add trusted location
 * @access Private
 */
router.post(
  '/trusted-locations',
  authenticate,
  validate(riskValidators.addTrustedLocation),
  riskController.addTrustedLocation
);

/**
 * @route DELETE /risk/trusted-locations/:id
 * @desc Remove trusted location
 * @access Private
 */
router.delete(
  '/trusted-locations/:id',
  authenticate,
  validate(riskValidators.removeTrustedLocation, { source: 'params' }),
  riskController.removeTrustedLocation
);

/**
 * @route GET /risk/recommendations
 * @desc Get security recommendations
 * @access Private
 */
router.get(
  '/recommendations',
  authenticate,
  validate(riskValidators.getSecurityRecommendations, { source: 'query' }),
  riskController.getSecurityRecommendations
);

/**
 * @route PUT /risk/recommendations/:id/dismiss
 * @desc Dismiss security recommendation
 * @access Private
 */
router.put(
  '/recommendations/:id/dismiss',
  authenticate,
  validate(riskValidators.dismissSecurityRecommendation, { source: 'params' }),
  riskController.dismissSecurityRecommendation
);

export const riskRoutes = router;
