import { z } from 'zod';

/**
 * SSO Validators
 * Comprehensive validation schemas for Single Sign-On operations
 */

/**
 * Common validation patterns
 */
const urlSchema = z.string().url('Invalid URL format').max(2000, 'URL is too long');

const entityIdSchema = z.string().min(1, 'Entity ID is required').max(255, 'Entity ID is too long');

const nameSchema = z
  .string()
  .min(1, 'Name is required')
  .max(100, 'Name is too long')
  .transform(name => name.trim());

/**
 * Context-aware validation
 */
export interface SSOValidationContext {
  requestMetadata?: {
    ipAddress?: string;
    userAgent?: string;
    origin?: string;
  };
  securityLevel?: 'standard' | 'high';
}

/**
 * SSO validators
 */
export const ssoValidators = {
  /**
   * Process SAML assertion validator
   * Validates request to process SAML assertion
   */
  processAssertion: z.object({
    SAMLResponse: z.string().min(1, 'SAML response is required'),
    RelayState: z.string().optional(),
  }),

  /**
   * Process SAML logout validator
   * Validates request to process SAML logout
   */
  processLogout: z.object({
    SAMLResponse: z.string().min(1, 'SAML response is required'),
    RelayState: z.string().optional(),
  }),

  /**
   * Create identity provider validator
   * Validates request to create an identity provider
   */
  createIdentityProvider: z.object({
    name: nameSchema,
    entityId: entityIdSchema,
    ssoUrl: urlSchema,
    sloUrl: urlSchema.optional(),
    certificate: z.string().optional(),
    isActive: z.boolean().optional().default(true),
    metadata: z.record(z.any()).optional(),
    attributeMapping: z.record(z.string()).optional(),
    nameIdFormat: z
      .enum([
        'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
      ])
      .optional()
      .default('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'),
    signatureAlgorithm: z
      .enum([
        'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
      ])
      .optional()
      .default('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'),
    digestAlgorithm: z
      .enum([
        'http://www.w3.org/2000/09/xmldsig#sha1',
        'http://www.w3.org/2001/04/xmlenc#sha256',
        'http://www.w3.org/2001/04/xmlenc#sha512',
      ])
      .optional()
      .default('http://www.w3.org/2001/04/xmlenc#sha256'),
    allowUnencryptedAssertions: z.boolean().optional().default(false),
    requireSignedAssertions: z.boolean().optional().default(true),
  }),

  /**
   * Update identity provider validator
   * Validates request to update an identity provider
   */
  updateIdentityProvider: z.object({
    name: nameSchema.optional(),
    entityId: entityIdSchema.optional(),
    ssoUrl: urlSchema.optional(),
    sloUrl: urlSchema.optional(),
    certificate: z.string().optional(),
    isActive: z.boolean().optional(),
    metadata: z.record(z.any()).optional(),
    attributeMapping: z.record(z.string()).optional(),
    nameIdFormat: z
      .enum([
        'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
      ])
      .optional(),
    signatureAlgorithm: z
      .enum([
        'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
      ])
      .optional(),
    digestAlgorithm: z
      .enum([
        'http://www.w3.org/2000/09/xmldsig#sha1',
        'http://www.w3.org/2001/04/xmlenc#sha256',
        'http://www.w3.org/2001/04/xmlenc#sha512',
      ])
      .optional(),
    allowUnencryptedAssertions: z.boolean().optional(),
    requireSignedAssertions: z.boolean().optional(),
  }),

  /**
   * Delete identity provider validator
   * Validates request to delete an identity provider
   */
  deleteIdentityProvider: z.object({
    id: z.string().min(1, 'Identity provider ID is required'),
  }),

  /**
   * Get identity provider validator
   * Validates request to get an identity provider
   */
  getIdentityProvider: z.object({
    id: z.string().min(1, 'Identity provider ID is required'),
  }),

  /**
   * List identity providers validator
   * Validates request to list identity providers
   */
  listIdentityProviders: z.object({
    includeInactive: z.boolean().optional().default(false),
  }),

  /**
   * Initiate login validator
   * Validates request to initiate SAML login
   */
  initiateLogin: z.object({
    idpId: z.string().min(1, 'Identity provider ID is required'),
    RelayState: z.string().optional(),
  }),

  /**
   * Terminate session validator
   * Validates request to terminate an SSO session
   */
  terminateSession: z.object({
    id: z.string().min(1, 'Session ID is required'),
  }),

  /**
   * Validation chain factory
   * Creates a validation chain with multiple validators
   */
  createValidationChain: <T extends z.ZodRawShape>(
    baseSchema: z.ZodObject<T>,
    options?: {
      securityLevel?: 'standard' | 'high';
      additionalChecks?: (data: any, context?: SSOValidationContext) => boolean | Promise<boolean>;
      errorMessage?: string;
      errorCode?: string;
    }
  ) => {
    const { securityLevel = 'standard', additionalChecks, errorMessage, errorCode } = options || {};

    // Apply different validation rules based on security level
    let schema = baseSchema;

    if (securityLevel === 'high') {
      // For high security, we might enforce stricter rules
      // This is just an example - in a real implementation, you would add specific rules
      if (schema.shape && 'allowUnencryptedAssertions' in schema.shape) {
        schema = schema.superRefine((data: any, ctx) => {
          if (data.allowUnencryptedAssertions === true) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: 'Unencrypted assertions are not allowed in high security mode',
              path: ['allowUnencryptedAssertions'],
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
