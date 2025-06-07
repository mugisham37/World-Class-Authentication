import { z } from 'zod';

/**
 * Risk Assessment Validators
 * Comprehensive validation schemas for risk assessment and fraud prevention operations
 */

/**
 * Common validation patterns
 */
const ipAddressSchema = z
  .string()
  .regex(
    /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/,
    'Invalid IP address format'
  )
  .optional();

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
export interface RiskValidationContext {
  requestMetadata?: {
    ipAddress?: string;
    userAgent?: string;
    deviceId?: string;
    location?: string;
  };
  userRole?: 'user' | 'admin' | 'security_analyst';
  riskScore?: number;
  securityLevel?: 'standard' | 'high' | 'paranoid';
}

/**
 * Risk validators
 */
export const riskValidators = {
  /**
   * Get risk assessment validator
   * Validates request to retrieve risk assessment for a user
   */
  getRiskAssessment: z.object({
    userId: z.string().uuid('Invalid user ID').optional(),
    includeFactors: z.boolean().optional().default(true),
    includeRecommendations: z.boolean().optional().default(true),
  }),

  /**
   * Get suspicious activities validator
   * Validates request to retrieve suspicious activities for a user
   */
  getSuspiciousActivities: z
    .object({
      ...paginationSchema.shape,
      userId: z.string().uuid('Invalid user ID').optional(),
      type: z
        .enum([
          'UNUSUAL_LOGIN_LOCATION',
          'MULTIPLE_FAILED_ATTEMPTS',
          'UNUSUAL_ACCOUNT_ACTIVITY',
          'SUSPICIOUS_IP_ADDRESS',
          'UNUSUAL_DEVICE',
          'UNUSUAL_TIME',
          'UNUSUAL_BEHAVIOR',
          'ALL',
        ])
        .optional()
        .default('ALL'),
      severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'ALL']).optional().default('ALL'),
      status: z.enum(['PENDING', 'RESOLVED', 'ALL']).optional().default('ALL'),
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
   * Resolve suspicious activity validator
   * Validates request to mark a suspicious activity as resolved
   */
  resolveSuspiciousActivity: z.object({
    id: z.string().min(1, 'Activity ID is required'),
    resolution: z.string().min(1, 'Resolution is required').max(1000, 'Resolution is too long'),
    notes: z.string().max(2000, 'Notes are too long').optional(),
  }),

  /**
   * Get trusted devices validator
   * Validates request to retrieve trusted devices for a user
   */
  getTrustedDevices: z.object({
    userId: z.string().uuid('Invalid user ID').optional(),
    includeInactive: z.boolean().optional().default(false),
  }),

  /**
   * Remove trusted device validator
   * Validates request to remove a trusted device
   */
  removeTrustedDevice: z.object({
    id: z.string().min(1, 'Device ID is required'),
  }),

  /**
   * Get trusted locations validator
   * Validates request to retrieve trusted locations for a user
   */
  getTrustedLocations: z.object({
    userId: z.string().uuid('Invalid user ID').optional(),
    includeInactive: z.boolean().optional().default(false),
  }),

  /**
   * Add trusted location validator
   * Validates request to add a trusted location
   */
  addTrustedLocation: z
    .object({
      name: z.string().min(1, 'Location name is required').max(100, 'Location name is too long'),
      ipRange: z
        .string()
        .regex(/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/, 'Invalid IP range format')
        .optional(),
      geoLocation: z
        .object({
          city: z.string().optional(),
          region: z.string().optional(),
          country: z.string().min(1, 'Country is required'),
          latitude: z.number().min(-90).max(90).optional(),
          longitude: z.number().min(-180).max(180).optional(),
          radius: z.number().positive().optional(), // Radius in kilometers
        })
        .optional(),
    })
    .refine(
      data => {
        // Either ipRange or geoLocation must be provided
        return !!data.ipRange || !!data.geoLocation;
      },
      {
        message: 'Either IP range or geo location is required',
        path: ['location'],
      }
    ),

  /**
   * Remove trusted location validator
   * Validates request to remove a trusted location
   */
  removeTrustedLocation: z.object({
    id: z.string().min(1, 'Location ID is required'),
  }),

  /**
   * Get security recommendations validator
   * Validates request to retrieve security recommendations for a user
   */
  getSecurityRecommendations: z.object({
    userId: z.string().uuid('Invalid user ID').optional(),
    includeDismissed: z.boolean().optional().default(false),
    priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'ALL']).optional().default('ALL'),
  }),

  /**
   * Dismiss security recommendation validator
   * Validates request to dismiss a security recommendation
   */
  dismissSecurityRecommendation: z.object({
    id: z.string().min(1, 'Recommendation ID is required'),
    reason: z.string().max(1000, 'Reason is too long').optional(),
  }),

  /**
   * Perform risk assessment validator
   * Validates request to perform a risk assessment for a user or action
   */
  performRiskAssessment: z.object({
    userId: z.string().uuid('Invalid user ID').optional(),
    actionType: z
      .enum([
        'LOGIN',
        'PASSWORD_CHANGE',
        'PROFILE_UPDATE',
        'PAYMENT',
        'WITHDRAWAL',
        'SENSITIVE_ACTION',
        'OTHER',
      ])
      .optional(),
    ipAddress: ipAddressSchema,
    userAgent: z.string().optional(),
    deviceId: z.string().optional(),
    location: z
      .object({
        city: z.string().optional(),
        region: z.string().optional(),
        country: z.string().optional(),
        latitude: z.number().min(-90).max(90).optional(),
        longitude: z.number().min(-180).max(180).optional(),
      })
      .optional(),
    contextData: z.record(z.any()).optional(),
  }),

  /**
   * Report suspicious activity validator
   * Validates request to report a suspicious activity
   */
  reportSuspiciousActivity: z.object({
    userId: z.string().uuid('Invalid user ID').optional(),
    activityType: z.enum([
      'UNAUTHORIZED_ACCESS',
      'ACCOUNT_TAKEOVER',
      'SUSPICIOUS_TRANSACTION',
      'UNUSUAL_BEHAVIOR',
      'OTHER',
    ]),
    description: z.string().min(1, 'Description is required').max(2000, 'Description is too long'),
    severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional().default('MEDIUM'),
    timestamp: z
      .string()
      .regex(
        /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$/,
        'Invalid date format. Use ISO 8601 format'
      )
      .optional(),
    ipAddress: ipAddressSchema,
    deviceInfo: z.string().optional(),
    additionalInfo: z.record(z.any()).optional(),
  }),

  /**
   * Get risk factors validator
   * Validates request to retrieve risk factors for a user
   */
  getRiskFactors: z.object({
    userId: z.string().uuid('Invalid user ID').optional(),
    includeInactive: z.boolean().optional().default(false),
    factorTypes: z.array(z.string()).optional(),
  }),

  /**
   * Update risk settings validator
   * Validates request to update risk assessment settings
   */
  updateRiskSettings: z
    .object({
      enabledFactors: z.array(z.string()).optional(),
      factorWeights: z.record(z.number().min(0).max(100)).optional(),
      thresholds: z
        .object({
          low: z.number().min(0).max(100).optional(),
          medium: z.number().min(0).max(100).optional(),
          high: z.number().min(0).max(100).optional(),
          critical: z.number().min(0).max(100).optional(),
        })
        .optional(),
      autoBlockThreshold: z.number().min(0).max(100).optional(),
      requireMfaThreshold: z.number().min(0).max(100).optional(),
      requireApprovalThreshold: z.number().min(0).max(100).optional(),
    })
    .refine(
      data => {
        // If thresholds are provided, ensure they are in ascending order
        if (data.thresholds) {
          const { low, medium, high, critical } = data.thresholds;
          if (low !== undefined && medium !== undefined && low >= medium) return false;
          if (medium !== undefined && high !== undefined && medium >= high) return false;
          if (high !== undefined && critical !== undefined && high >= critical) return false;
        }
        return true;
      },
      {
        message: 'Risk thresholds must be in ascending order (low < medium < high < critical)',
        path: ['thresholds'],
      }
    ),

  /**
   * Get risk events validator
   * Validates request to retrieve risk events
   */
  getRiskEvents: z
    .object({
      ...paginationSchema.shape,
      userId: z.string().uuid('Invalid user ID').optional(),
      eventType: z.string().optional(),
      severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'ALL']).optional().default('ALL'),
      startDate: dateSchema,
      endDate: dateSchema,
      outcome: z
        .enum(['ALLOWED', 'BLOCKED', 'CHALLENGED', 'FLAGGED', 'ALL'])
        .optional()
        .default('ALL'),
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
   * Device fingerprinting validator
   * Validates device fingerprinting data
   */
  deviceFingerprint: z.object({
    userAgent: z.string().optional(),
    screenResolution: z.string().optional(),
    colorDepth: z.number().int().optional(),
    timezone: z.string().optional(),
    timezoneOffset: z.number().int().optional(),
    platform: z.string().optional(),
    plugins: z.array(z.string()).optional(),
    fonts: z.array(z.string()).optional(),
    localStorage: z.boolean().optional(),
    sessionStorage: z.boolean().optional(),
    cookiesEnabled: z.boolean().optional(),
    language: z.string().optional(),
    canvas: z.string().optional(),
    webgl: z.string().optional(),
    adBlock: z.boolean().optional(),
    touchSupport: z.boolean().optional(),
    hardwareConcurrency: z.number().int().optional(),
    deviceMemory: z.number().optional(),
    audioFingerprint: z.string().optional(),
    batteryLevel: z.number().min(0).max(1).optional(),
    batteryCharging: z.boolean().optional(),
    doNotTrack: z.boolean().optional(),
    webdriver: z.boolean().optional(),
    incognito: z.boolean().optional(),
    additionalData: z.record(z.any()).optional(),
  }),

  /**
   * IP risk assessment validator
   * Validates request to assess risk of an IP address
   */
  assessIpRisk: z.object({
    ipAddress: z
      .string()
      .regex(
        /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/,
        'Invalid IP address format'
      ),
    userId: z.string().uuid('Invalid user ID').optional(),
    context: z.string().optional(),
  }),

  /**
   * Validation chain factory
   * Creates a validation chain with multiple validators
   */
  createValidationChain: <T extends z.ZodRawShape>(
    baseSchema: z.ZodObject<T>,
    options?: {
      securityLevel?: 'standard' | 'high' | 'paranoid';
      additionalChecks?: (data: any, context?: RiskValidationContext) => boolean | Promise<boolean>;
      errorMessage?: string;
      errorCode?: string;
    }
  ) => {
    const { additionalChecks, errorMessage, errorCode } = options || {};

    // Apply different validation rules based on security level
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

  /**
   * Fraud detection validation
   * Validates if a request is potentially fraudulent
   */
  validateFraudRisk: (): { isValid: boolean; riskScore: number; reason?: string } => {
    // This is a placeholder for actual fraud detection logic
    // In a real implementation, this would use machine learning models and risk rules
    const riskScore = Math.random() * 100;
    return {
      isValid: riskScore < 75,
      riskScore,
      reason: riskScore >= 75 ? 'Suspicious activity detected' : undefined,
    };
  },

  /**
   * Velocity check validation
   * Validates if the request frequency is within acceptable limits
   */
  validateVelocity: (
    maxActions: number = 10
  ): { isValid: boolean; currentCount: number; maxAllowed: number } => {
    // This is a placeholder for actual velocity check logic
    // In a real implementation, this would check a database or cache
    return {
      isValid: true,
      currentCount: 5,
      maxAllowed: maxActions,
    };
  },
};
