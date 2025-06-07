import { Router } from 'express';
import { healthController } from '../controllers';

/**
 * Health check routes
 * Provides endpoints to check the health of the application and its dependencies
 */
const router = Router();

/**
 * @route GET /health
 * @desc Basic health check endpoint
 * @access Public
 */
router.get('/', healthController.getHealth);

/**
 * @route GET /health/detailed
 * @desc Detailed health check with component status
 * @access Public
 */
router.get('/detailed', healthController.getDetailedHealth);

/**
 * @route GET /health/ready
 * @desc Readiness check for load balancers
 * @access Public
 */
router.get('/ready', healthController.getReadiness);

/**
 * @route GET /health/live
 * @desc Liveness check for orchestrators
 * @access Public
 */
router.get('/live', healthController.getLiveness);

/**
 * @route GET /health/metrics
 * @desc Application metrics for monitoring systems
 * @access Public
 */
router.get('/metrics', healthController.getMetrics);

export const healthRoutes = router;
