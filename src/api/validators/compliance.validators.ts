import { z } from 'zod';

/**
 * Compliance Validators
 * Comprehensive validation schemas for compliance-related operations
 */

/**
 * Common validation patterns
 */
const emailSchema = z
  .string()
  .email('Invalid email address')
  .min(1, 'Email is required')
  .max(255, 'Email is too long')
  .transform(email => email.toLowerCase().trim());

const paginationSchema = z.object({
  page: z.coerce.number().int().positive().optional().default(1),
  limit: z.coerce.number().int().positive().max(100).optional().default(20),
});

/**
 * Context-aware validation
 */
export interface ComplianceValidationContext {
  requestMetadata?: {
    ipAddress?: string;
    userAgent?: string;
  };
  userRole?: 'user' | 'admin' | 'compliance_officer';
  jurisdictions?: string[];
  applicableRegulations?: string[];
}

/**
 * Compliance validators
 */
export const complianceValidators = {
  /**
   * Submit a data subject request (DSR) validator
   */
  submitDataRequest: z.object({
    type: z.enum(
      [
        'DATA_ACCESS',
        'DATA_DELETION',
        'DATA_CORRECTION',
        'DATA_PORTABILITY',
        'PROCESSING_RESTRICTION',
        'PROCESSING_OBJECTION',
      ],
      {
        errorMap: () => ({ message: 'Invalid request type' }),
      }
    ),
    email: emailSchema,
    firstName: z.string().min(1, 'First name is required').max(100, 'First name is too long'),
    lastName: z.string().min(1, 'Last name is required').max(100, 'Last name is too long'),
    reason: z.string().max(1000, 'Reason is too long').optional(),
    proofOfIdentity: z.string().optional(), // This would typically be a file reference or base64 encoded document
    additionalInfo: z.record(z.any()).optional(),
  }),

  /**
   * Get data subject request status validator
   */
  getDataRequestStatus: z.object({
    id: z.string().min(1, 'Request ID is required'),
  }),

  /**
   * Get user's data subject requests validator
   */
  getUserDataRequests: z.object({
    ...paginationSchema.shape,
    status: z
      .enum(['PENDING', 'PROCESSING', 'COMPLETED', 'REJECTED', 'ALL'])
      .optional()
      .default('ALL'),
    type: z
      .enum([
        'DATA_ACCESS',
        'DATA_DELETION',
        'DATA_CORRECTION',
        'DATA_PORTABILITY',
        'PROCESSING_RESTRICTION',
        'PROCESSING_OBJECTION',
        'ALL',
      ])
      .optional()
      .default('ALL'),
  }),

  /**
   * Cancel a data subject request validator
   */
  cancelDataRequest: z.object({
    id: z.string().min(1, 'Request ID is required'),
  }),

  /**
   * Get privacy policy validator
   */
  getPrivacyPolicy: z.object({
    version: z.string().optional(),
    language: z
      .string()
      .length(2, 'Language code must be 2 characters (ISO 639-1)')
      .optional()
      .default('en'),
  }),

  /**
   * Get terms of service validator
   */
  getTermsOfService: z.object({
    version: z.string().optional(),
    language: z
      .string()
      .length(2, 'Language code must be 2 characters (ISO 639-1)')
      .optional()
      .default('en'),
  }),

  /**
   * Get cookie policy validator
   */
  getCookiePolicy: z.object({
    version: z.string().optional(),
    language: z
      .string()
      .length(2, 'Language code must be 2 characters (ISO 639-1)')
      .optional()
      .default('en'),
  }),

  /**
   * Update user cookie preferences validator
   */
  updateCookiePreferences: z.object({
    preferences: z.object({
      essential: z.literal(true), // Essential cookies are always required
      performance: z.boolean().optional().default(false),
      functional: z.boolean().optional().default(false),
      targeting: z.boolean().optional().default(false),
      thirdParty: z.boolean().optional().default(false),
    }),
    consentVersion: z.string().optional(),
  }),

  /**
   * Get data processing records validator
   */
  getDataProcessingRecords: z.object({
    ...paginationSchema.shape,
    category: z.string().optional(),
    purpose: z.string().optional(),
    legalBasis: z
      .enum([
        'CONSENT',
        'CONTRACT',
        'LEGAL_OBLIGATION',
        'VITAL_INTEREST',
        'PUBLIC_INTEREST',
        'LEGITIMATE_INTEREST',
        'ALL',
      ])
      .optional()
      .default('ALL'),
    crossBorderTransfers: z.boolean().optional(),
  }),

  /**
   * Consent management validator
   */
  updateConsentPreferences: z.object({
    marketingEmail: z.boolean().optional(),
    marketingSms: z.boolean().optional(),
    marketingPhone: z.boolean().optional(),
    thirdPartySharing: z.boolean().optional(),
    analyticsUsage: z.boolean().optional(),
    profileEnrichment: z.boolean().optional(),
    consentVersion: z.string().optional(),
  }),

  /**
   * Data retention policy validator
   */
  getDataRetentionPolicy: z.object({
    dataCategory: z.string().optional(),
    jurisdiction: z.string().optional(),
  }),

  /**
   * Breach notification validator
   */
  submitBreachNotification: z.object({
    incidentDate: z
      .string()
      .regex(
        /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$/,
        'Invalid date format. Use ISO 8601 format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)'
      ),
    discoveryDate: z
      .string()
      .regex(
        /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$/,
        'Invalid date format. Use ISO 8601 format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)'
      ),
    description: z.string().min(1, 'Description is required').max(5000, 'Description is too long'),
    dataCategories: z.array(z.string()).min(1, 'At least one data category is required'),
    affectedUserCount: z
      .number()
      .int()
      .min(0, 'Affected user count must be a non-negative integer'),
    potentialImpact: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
    mitigationSteps: z
      .string()
      .min(1, 'Mitigation steps are required')
      .max(5000, 'Mitigation steps are too long'),
    notificationPlan: z.string().max(5000, 'Notification plan is too long').optional(),
    contactPerson: z.object({
      name: z.string().min(1, 'Contact name is required'),
      email: emailSchema,
      phone: z.string().optional(),
      role: z.string().optional(),
    }),
  }),

  /**
   * Compliance report validator
   */
  generateComplianceReport: z
    .object({
      reportType: z.enum([
        'GDPR_COMPLIANCE',
        'CCPA_COMPLIANCE',
        'HIPAA_COMPLIANCE',
        'PCI_DSS_COMPLIANCE',
        'CUSTOM',
      ]),
      startDate: z
        .string()
        .regex(
          /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$/,
          'Invalid date format. Use ISO 8601 format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)'
        ),
      endDate: z
        .string()
        .regex(
          /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$/,
          'Invalid date format. Use ISO 8601 format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)'
        ),
      format: z.enum(['PDF', 'CSV', 'JSON', 'HTML']).optional().default('PDF'),
      includeMetrics: z.boolean().optional().default(true),
      includeIncidents: z.boolean().optional().default(true),
      includeRequests: z.boolean().optional().default(true),
      customFields: z.array(z.string()).optional(),
    })
    .refine(
      data => {
        // Ensure startDate is before or equal to endDate
        return new Date(data.startDate) <= new Date(data.endDate);
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
      userRole?: 'user' | 'admin' | 'compliance_officer';
      additionalChecks?: (
        data: any,
        context?: ComplianceValidationContext
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
