import { Router } from 'express';
import { performanceController } from '../controllers';
import { authenticate } from '../middlewares/auth.middleware';
import { validate } from '../middlewares/input-validation.middleware';
import { performanceValidators } from '../validators/performance.validators';

/**
 * Performance routes
 * Handles performance monitoring and metrics endpoints
 */
const router = Router();

/**
 * @route GET /performance/metrics
 * @desc Get system metrics
 * @access Private/Admin
 */
router.get('/metrics', authenticate, performanceController.getMetrics);

/**
 * @route GET /performance/dashboard
 * @desc Get performance dashboard data
 * @access Private/Admin
 */
router.get(
  '/dashboard',
  authenticate,
  validate(performanceValidators.getDashboardData, { source: 'query' }),
  performanceController.getDashboardData
);

/**
 * @route GET /performance/real-time
 * @desc Get real-time performance data
 * @access Private/Admin
 */
router.get(
  '/real-time',
  authenticate,
  validate(performanceValidators.getRealTimeData, { source: 'query' }),
  performanceController.getRealTimeData
);

/**
 * @route GET /performance/alerts
 * @desc Get performance alerts
 * @access Private/Admin
 */
router.get(
  '/alerts',
  authenticate,
  validate(performanceValidators.getAlerts, { source: 'query' }),
  performanceController.getAlerts
);

/**
 * @route GET /performance/database
 * @desc Get database performance metrics
 * @access Private/Admin
 */
router.get(
  '/database',
  authenticate,
  validate(performanceValidators.getDatabaseMetrics, { source: 'query' }),
  performanceController.getDatabaseMetrics
);

/**
 * @route GET /performance/cache
 * @desc Get cache performance metrics
 * @access Private/Admin
 */
router.get(
  '/cache',
  authenticate,
  validate(performanceValidators.getCacheMetrics, { source: 'query' }),
  performanceController.getCacheMetrics
);

/**
 * @route GET /performance/endpoints
 * @desc Get endpoint performance metrics
 * @access Private/Admin
 */
router.get(
  '/endpoints',
  authenticate,
  validate(performanceValidators.getEndpointMetrics, { source: 'query' }),
  performanceController.getEndpointMetrics
);

export const performanceRoutes = router;
