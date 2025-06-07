import { z } from 'zod';

/**
 * Performance Validators
 * Comprehensive validation schemas for performance monitoring operations
 */

/**
 * Common validation patterns
 */
const paginationSchema = z.object({
  page: z.coerce.number().int().positive().optional().default(1),
  limit: z.coerce.number().int().positive().max(100).optional().default(20),
});

/**
 * Context-aware validation
 */
export interface PerformanceValidationContext {
  requestMetadata?: {
    ipAddress?: string;
    userAgent?: string;
  };
  userRole?: 'user' | 'admin' | 'system';
}

/**
 * Performance validators
 */
export const performanceValidators = {
  /**
   * Get dashboard data validator
   * Validates query parameters for retrieving performance dashboard data
   */
  getDashboardData: z.object({
    timeRange: z.enum(['1h', '6h', '12h', '24h', '7d', '30d']).optional().default('24h'),
  }),

  /**
   * Get real-time data validator
   * Validates query parameters for retrieving real-time performance data
   */
  getRealTimeData: z.object({
    metrics: z.array(z.string()).optional(),
  }),

  /**
   * Get alerts validator
   * Validates query parameters for retrieving performance alerts
   */
  getAlerts: z.object({
    status: z.enum(['active', 'resolved', 'all']).optional().default('active'),
    severity: z.enum(['low', 'medium', 'high', 'critical', 'all']).optional().default('all'),
    timeRange: z.enum(['1h', '6h', '12h', '24h', '7d', '30d']).optional().default('24h'),
  }),

  /**
   * Get database metrics validator
   * Validates query parameters for retrieving database performance metrics
   */
  getDatabaseMetrics: z.object({
    includeQueries: z.boolean().optional().default(true),
    includeTables: z.boolean().optional().default(true),
  }),

  /**
   * Get cache metrics validator
   * Validates query parameters for retrieving cache performance metrics
   */
  getCacheMetrics: z.object({
    includeKeys: z.boolean().optional().default(true),
    keyPrefix: z.string().optional(),
  }),

  /**
   * Get endpoint metrics validator
   * Validates query parameters for retrieving endpoint performance metrics
   */
  getEndpointMetrics: z.object({
    ...paginationSchema.shape,
    sort: z.enum(['requests', 'response_time', 'error_rate']).optional().default('requests'),
    method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'ALL']).optional().default('ALL'),
    minRequests: z.coerce.number().int().nonnegative().optional(),
    timeRange: z.enum(['1h', '6h', '12h', '24h', '7d', '30d']).optional().default('24h'),
  }),

  /**
   * Validation chain factory
   * Creates a validation chain with multiple validators
   */
  createValidationChain: <T extends z.ZodRawShape>(
    baseSchema: z.ZodObject<T>,
    options?: {
      userRole?: 'user' | 'admin' | 'system';
      additionalChecks?: (
        data: any,
        context?: PerformanceValidationContext
      ) => boolean | Promise<boolean>;
      errorMessage?: string;
      errorCode?: string;
    }
  ) => {
    const { additionalChecks, errorMessage, errorCode } = options || {};

    // Apply different validation rules based on user role
    let schema = baseSchema;

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
