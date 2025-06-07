import { Router } from 'express';
import { auditController } from '../controllers';
import { authenticate } from '../middlewares/auth.middleware';

/**
 * Audit routes
 * Handles audit log access and management
 */
const router = Router();

/**
 * @route GET /audit/logs
 * @desc Get audit logs
 * @access Private/Admin
 */
router.get('/logs', authenticate, auditController.getAuditLogs);

/**
 * @route GET /audit/logs/:id
 * @desc Get audit log by ID
 * @access Private/Admin
 */
router.get('/logs/:id', authenticate, auditController.getAuditLogById);

/**
 * @route GET /audit/users/:userId/activity
 * @desc Get user activity audit logs
 * @access Private
 */
router.get('/users/:userId/activity', authenticate, auditController.getUserActivityLogs);

/**
 * @route GET /audit/security-events
 * @desc Get security events
 * @access Private/Admin
 */
router.get('/security-events', authenticate, auditController.getSecurityEvents);

/**
 * @route GET /audit/export
 * @desc Export audit logs
 * @access Private/Admin
 */
router.get('/export', authenticate, auditController.exportAuditLogs);

export const auditRoutes = router;
