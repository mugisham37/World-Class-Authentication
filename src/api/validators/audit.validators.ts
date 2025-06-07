import { z } from 'zod';

/**
 * Audit Validators
 * Comprehensive validation schemas for audit-related operations
 */

/**
 * Common validation patterns
 */
const dateSchema = z
  .string()
  .regex(
    /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$/,
    'Invalid date format. Use ISO 8601 format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)'
  )
  .optional();

const paginationSchema = z.object({
  page: z.coerce.number().int().positive().optional().default(1),
  limit: z.coerce.number().int().positive().max(100).optional().default(20),
});

/**
 * Context-aware validation
 */
export interface AuditValidationContext {
  requestMetadata?: {
    ipAddress?: string;
    userAgent?: string;
  };
  userRole?: 'user' | 'admin' | 'auditor';
  complianceRequirements?: string[];
}

/**
 * Audit validators
 */
export const auditValidators = {
  /**
   * Get audit logs validator
   * Validates query parameters for retrieving audit logs
   */
  getAuditLogs: z
    .object({
      ...paginationSchema.shape,
      userId: z.string().uuid('Invalid user ID').optional(),
      actionType: z.string().optional(),
      startDate: dateSchema,
      endDate: dateSchema,
      resource: z.string().optional(),
      severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
    })
    .refine(
      data => {
        // If both dates are provided, ensure startDate is before or equal to endDate
        if (data.startDate && data.endDate) {
          return new Date(data.startDate) <= new Date(data.endDate);
        }
        return true;
      },
      {
        message: 'Start date must be before or equal to end date',
        path: ['dateRange'],
      }
    ),

  /**
   * Get audit log by ID validator
   * Validates path parameters for retrieving a specific audit log
   */
  getAuditLogById: z.object({
    id: z.string().min(1, 'Audit log ID is required'),
  }),

  /**
   * Get user activity logs validator
   * Validates query parameters for retrieving user activity logs
   */
  getUserActivityLogs: z
    .object({
      ...paginationSchema.shape,
      userId: z.string().uuid('Invalid user ID'),
      actionType: z.string().optional(),
      startDate: dateSchema,
      endDate: dateSchema,
    })
    .refine(
      data => {
        // If both dates are provided, ensure startDate is before or equal to endDate
        if (data.startDate && data.endDate) {
          return new Date(data.startDate) <= new Date(data.endDate);
        }
        return true;
      },
      {
        message: 'Start date must be before or equal to end date',
        path: ['dateRange'],
      }
    ),

  /**
   * Get security events validator
   * Validates query parameters for retrieving security events
   */
  getSecurityEvents: z
    .object({
      ...paginationSchema.shape,
      severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
      eventType: z.string().optional(),
      startDate: dateSchema,
      endDate: dateSchema,
      status: z.enum(['PENDING', 'RESOLVED', 'ALL']).optional().default('ALL'),
    })
    .refine(
      data => {
        // If both dates are provided, ensure startDate is before or equal to endDate
        if (data.startDate && data.endDate) {
          return new Date(data.startDate) <= new Date(data.endDate);
        }
        return true;
      },
      {
        message: 'Start date must be before or equal to end date',
        path: ['dateRange'],
      }
    ),

  /**
   * Export audit logs validator
   * Validates query parameters for exporting audit logs
   */
  exportAuditLogs: z
    .object({
      userId: z.string().uuid('Invalid user ID').optional(),
      actionType: z.string().optional(),
      startDate: dateSchema,
      endDate: dateSchema,
      resource: z.string().optional(),
      format: z.enum(['json', 'csv']).optional().default('json'),
    })
    .refine(
      data => {
        // If both dates are provided, ensure startDate is before or equal to endDate
        if (data.startDate && data.endDate) {
          return new Date(data.startDate) <= new Date(data.endDate);
        }
        return true;
      },
      {
        message: 'Start date must be before or equal to end date',
        path: ['dateRange'],
      }
    ),

  /**
   * Validation chain factory
   * Creates a validation chain with multiple validators
   */
  createValidationChain: <T extends z.ZodRawShape>(
    baseSchema: z.ZodObject<T>,
    options?: {
      userRole?: 'user' | 'admin' | 'auditor';
      additionalChecks?: (
        data: any,
        context?: AuditValidationContext
      ) => boolean | Promise<boolean>;
      errorMessage?: string;
      errorCode?: string;
    }
  ) => {
    const { userRole = 'user', additionalChecks, errorMessage, errorCode } = options || {};

    // Apply different validation rules based on user role
    let schema = baseSchema;

    if (userRole === 'user') {
      // Regular users can only access their own data
      if (schema.shape && 'userId' in schema.shape) {
        // Use type assertion to handle the refinement properly
        schema = schema.superRefine((data, ctx) => {
          if (data['userId'] !== 'currentUser') {
            // Use bracket notation
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: 'You can only access your own audit logs',
              path: ['userId'],
            });
          }
        }) as unknown as z.ZodObject<T>;
      }
    }

    // Add custom validation if provided
    if (additionalChecks) {
      return schema.superRefine((data, ctx) => {
        const result = additionalChecks(data);
        if (!result) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: errorMessage || 'Validation failed',
            path: ['_custom'],
            params: { code: errorCode || 'VALIDATION_ERROR' },
          });
        }
      }) as unknown as z.ZodObject<T>;
    }

    return schema;
  },
};
