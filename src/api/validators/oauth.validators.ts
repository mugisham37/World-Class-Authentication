import { z } from 'zod';

/**
 * OAuth Validators
 * Comprehensive validation schemas for OAuth 2.0 and OpenID Connect operations
 */

/**
 * Common validation patterns
 */
const uriSchema = z.string().url('Invalid URI format').max(2000, 'URI is too long');

const scopeSchema = z
  .string()
  .max(1000, 'Scope string is too long')
  .transform(scope => scope.trim())
  .optional();

/**
 * Context-aware validation
 */
export interface OAuthValidationContext {
  requestMetadata?: {
    ipAddress?: string;
    userAgent?: string;
  };
  clientType?: 'confidential' | 'public';
  securityLevel?: 'standard' | 'high';
  riskScore?: number;
}

/**
 * OAuth validators
 */
export const oauthValidators = {
  /**
   * Authorize endpoint validator
   */
  authorize: z
    .object({
      response_type: z.enum(
        [
          'code',
          'token',
          'id_token',
          'code token',
          'code id_token',
          'token id_token',
          'code token id_token',
        ],
        {
          errorMap: () => ({ message: 'Invalid response type' }),
        }
      ),
      client_id: z.string().min(1, 'Client ID is required'),
      redirect_uri: uriSchema,
      scope: scopeSchema,
      state: z.string().optional(),
      nonce: z.string().optional(),
      prompt: z.enum(['none', 'login', 'consent', 'select_account']).optional(),
      max_age: z.coerce.number().int().nonnegative().optional(),
      ui_locales: z.string().optional(),
      id_token_hint: z.string().optional(),
      login_hint: z.string().optional(),
      acr_values: z.string().optional(),
      code_challenge: z.string().optional(),
      code_challenge_method: z.enum(['plain', 'S256']).optional(),
    })
    .refine(
      data => {
        // If code_challenge is provided, code_challenge_method should also be provided
        if (data.code_challenge && !data.code_challenge_method) {
          return false;
        }
        return true;
      },
      {
        message: 'code_challenge_method is required when code_challenge is provided',
        path: ['code_challenge_method'],
      }
    ),

  /**
   * Token endpoint validator
   */
  token: z
    .object({
      grant_type: z.enum(
        [
          'authorization_code',
          'refresh_token',
          'client_credentials',
          'password',
          'urn:ietf:params:oauth:grant-type:device_code',
          'urn:ietf:params:oauth:grant-type:jwt-bearer',
        ],
        {
          errorMap: () => ({ message: 'Invalid grant type' }),
        }
      ),
      code: z.string().optional(),
      redirect_uri: uriSchema.optional(),
      client_id: z.string().optional(),
      client_secret: z.string().optional(),
      refresh_token: z.string().optional(),
      scope: scopeSchema,
      username: z.string().optional(),
      password: z.string().optional(),
      code_verifier: z.string().optional(),
      device_code: z.string().optional(),
      assertion: z.string().optional(),
    })
    .superRefine((data, ctx) => {
      // Validate required fields based on grant_type
      if (data.grant_type === 'authorization_code') {
        if (!data.code) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'Authorization code is required for authorization_code grant type',
            path: ['code'],
          });
        }
        if (!data.redirect_uri) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'Redirect URI is required for authorization_code grant type',
            path: ['redirect_uri'],
          });
        }
      } else if (data.grant_type === 'refresh_token') {
        if (!data.refresh_token) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'Refresh token is required for refresh_token grant type',
            path: ['refresh_token'],
          });
        }
      } else if (data.grant_type === 'password') {
        if (!data.username) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'Username is required for password grant type',
            path: ['username'],
          });
        }
        if (!data.password) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'Password is required for password grant type',
            path: ['password'],
          });
        }
      } else if (data.grant_type === 'urn:ietf:params:oauth:grant-type:device_code') {
        if (!data.device_code) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'Device code is required for device_code grant type',
            path: ['device_code'],
          });
        }
      } else if (data.grant_type === 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
        if (!data.assertion) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'Assertion is required for jwt-bearer grant type',
            path: ['assertion'],
          });
        }
      }

      // Validate PKCE
      if (data.grant_type === 'authorization_code' && data.code_verifier) {
        // Code verifier should be between 43 and 128 characters
        if (data.code_verifier.length < 43 || data.code_verifier.length > 128) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'Code verifier must be between 43 and 128 characters',
            path: ['code_verifier'],
          });
        }
        // Code verifier should only contain alphanumeric characters, hyphens, underscores, periods, and tildes
        if (!/^[A-Za-z0-9\-._~]+$/.test(data.code_verifier)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message:
              'Code verifier can only contain alphanumeric characters, hyphens, underscores, periods, and tildes',
            path: ['code_verifier'],
          });
        }
      }
    }),

  /**
   * Revoke token endpoint validator
   */
  revokeToken: z.object({
    token: z.string().min(1, 'Token is required'),
    token_type_hint: z.enum(['access_token', 'refresh_token']).optional(),
    client_id: z.string().min(1, 'Client ID is required'),
    client_secret: z.string().optional(),
  }),

  /**
   * Introspect token endpoint validator
   */
  introspectToken: z.object({
    token: z.string().min(1, 'Token is required'),
    token_type_hint: z.enum(['access_token', 'refresh_token']).optional(),
    client_id: z.string().min(1, 'Client ID is required'),
    client_secret: z.string().optional(),
  }),

  /**
   * Device authorization endpoint validator
   */
  deviceAuthorization: z.object({
    client_id: z.string().min(1, 'Client ID is required'),
    client_secret: z.string().optional(),
    scope: scopeSchema,
  }),

  /**
   * Client registration validator
   */
  registerClient: z
    .object({
      client_name: z.string().min(1, 'Client name is required'),
      redirect_uris: z.array(uriSchema).min(1, 'At least one redirect URI is required'),
      token_endpoint_auth_method: z
        .enum([
          'none',
          'client_secret_basic',
          'client_secret_post',
          'client_secret_jwt',
          'private_key_jwt',
        ])
        .default('client_secret_basic'),
      grant_types: z
        .array(
          z.enum([
            'authorization_code',
            'implicit',
            'refresh_token',
            'client_credentials',
            'password',
            'urn:ietf:params:oauth:grant-type:device_code',
            'urn:ietf:params:oauth:grant-type:jwt-bearer',
          ])
        )
        .default(['authorization_code']),
      response_types: z
        .array(
          z.enum([
            'code',
            'token',
            'id_token',
            'code token',
            'code id_token',
            'token id_token',
            'code token id_token',
          ])
        )
        .default(['code']),
      client_uri: uriSchema.optional(),
      logo_uri: uriSchema.optional(),
      scope: scopeSchema,
      contacts: z.array(z.string().email('Invalid email format')).optional(),
      tos_uri: uriSchema.optional(),
      policy_uri: uriSchema.optional(),
      jwks_uri: uriSchema.optional(),
      jwks: z.record(z.any()).optional(),
      software_id: z.string().optional(),
      software_version: z.string().optional(),
      // Additional fields for OpenID Connect
      application_type: z.enum(['web', 'native']).default('web'),
      sector_identifier_uri: uriSchema.optional(),
      subject_type: z.enum(['pairwise', 'public']).default('public'),
      id_token_signed_response_alg: z.string().default('RS256'),
      id_token_encrypted_response_alg: z.string().optional(),
      id_token_encrypted_response_enc: z.string().optional(),
      userinfo_signed_response_alg: z.string().optional(),
      userinfo_encrypted_response_alg: z.string().optional(),
      userinfo_encrypted_response_enc: z.string().optional(),
      request_object_signing_alg: z.string().optional(),
      request_object_encryption_alg: z.string().optional(),
      request_object_encryption_enc: z.string().optional(),
      token_endpoint_auth_signing_alg: z.string().optional(),
      default_max_age: z.number().int().nonnegative().optional(),
      require_auth_time: z.boolean().default(false),
      default_acr_values: z.array(z.string()).optional(),
      initiate_login_uri: uriSchema.optional(),
      request_uris: z.array(uriSchema).optional(),
      post_logout_redirect_uris: z.array(uriSchema).optional(),
      backchannel_logout_uri: uriSchema.optional(),
      backchannel_logout_session_required: z.boolean().default(false),
      frontchannel_logout_uri: uriSchema.optional(),
      frontchannel_logout_session_required: z.boolean().default(false),
    })
    .refine(
      data => {
        // If jwks and jwks_uri are both provided, it's an error
        if (data.jwks && data.jwks_uri) {
          return false;
        }
        return true;
      },
      {
        message: 'Both jwks and jwks_uri cannot be provided simultaneously',
        path: ['jwks'],
      }
    ),

  /**
   * Update client validator
   */
  updateClient: z
    .object({
      client_id: z.string().min(1, 'Client ID is required'),
      client_name: z.string().optional(),
      redirect_uris: z.array(uriSchema).optional(),
      token_endpoint_auth_method: z
        .enum([
          'none',
          'client_secret_basic',
          'client_secret_post',
          'client_secret_jwt',
          'private_key_jwt',
        ])
        .optional(),
      grant_types: z
        .array(
          z.enum([
            'authorization_code',
            'implicit',
            'refresh_token',
            'client_credentials',
            'password',
            'urn:ietf:params:oauth:grant-type:device_code',
            'urn:ietf:params:oauth:grant-type:jwt-bearer',
          ])
        )
        .optional(),
      response_types: z
        .array(
          z.enum([
            'code',
            'token',
            'id_token',
            'code token',
            'code id_token',
            'token id_token',
            'code token id_token',
          ])
        )
        .optional(),
      client_uri: uriSchema.optional(),
      logo_uri: uriSchema.optional(),
      scope: scopeSchema,
      contacts: z.array(z.string().email('Invalid email format')).optional(),
      tos_uri: uriSchema.optional(),
      policy_uri: uriSchema.optional(),
      jwks_uri: uriSchema.optional(),
      jwks: z.record(z.any()).optional(),
      software_id: z.string().optional(),
      software_version: z.string().optional(),
      // Additional fields for OpenID Connect
      application_type: z.enum(['web', 'native']).optional(),
      sector_identifier_uri: uriSchema.optional(),
      subject_type: z.enum(['pairwise', 'public']).optional(),
      id_token_signed_response_alg: z.string().optional(),
      id_token_encrypted_response_alg: z.string().optional(),
      id_token_encrypted_response_enc: z.string().optional(),
      userinfo_signed_response_alg: z.string().optional(),
      userinfo_encrypted_response_alg: z.string().optional(),
      userinfo_encrypted_response_enc: z.string().optional(),
      request_object_signing_alg: z.string().optional(),
      request_object_encryption_alg: z.string().optional(),
      request_object_encryption_enc: z.string().optional(),
      token_endpoint_auth_signing_alg: z.string().optional(),
      default_max_age: z.number().int().nonnegative().optional(),
      require_auth_time: z.boolean().optional(),
      default_acr_values: z.array(z.string()).optional(),
      initiate_login_uri: uriSchema.optional(),
      request_uris: z.array(uriSchema).optional(),
      post_logout_redirect_uris: z.array(uriSchema).optional(),
      backchannel_logout_uri: uriSchema.optional(),
      backchannel_logout_session_required: z.boolean().optional(),
      frontchannel_logout_uri: uriSchema.optional(),
      frontchannel_logout_session_required: z.boolean().optional(),
    })
    .refine(
      data => {
        // If jwks and jwks_uri are both provided, it's an error
        if (data.jwks && data.jwks_uri) {
          return false;
        }
        return true;
      },
      {
        message: 'Both jwks and jwks_uri cannot be provided simultaneously',
        path: ['jwks'],
      }
    ),

  /**
   * Delete client validator
   */
  deleteClient: z.object({
    client_id: z.string().min(1, 'Client ID is required'),
  }),

  /**
   * Get client validator
   */
  getClient: z.object({
    client_id: z.string().min(1, 'Client ID is required'),
  }),

  /**
   * List clients validator
   */
  listClients: z.object({
    page: z.coerce.number().int().positive().optional().default(1),
    limit: z.coerce.number().int().positive().max(100).optional().default(20),
    filter: z.string().optional(),
  }),

  /**
   * Rotate client secret validator
   */
  rotateClientSecret: z.object({
    client_id: z.string().min(1, 'Client ID is required'),
  }),

  /**
   * End session validator (OpenID Connect)
   */
  endSession: z
    .object({
      id_token_hint: z.string().optional(),
      post_logout_redirect_uri: uriSchema.optional(),
      state: z.string().optional(),
    })
    .refine(
      data => {
        // If post_logout_redirect_uri is provided, id_token_hint should also be provided
        if (data.post_logout_redirect_uri && !data.id_token_hint) {
          return false;
        }
        return true;
      },
      {
        message: 'id_token_hint is required when post_logout_redirect_uri is provided',
        path: ['id_token_hint'],
      }
    ),

  /**
   * Validation chain factory
   * Creates a validation chain with multiple validators
   */
  createValidationChain: <T extends z.ZodRawShape>(
    baseSchema: z.ZodObject<T>,
    options?: {
      clientType?: 'confidential' | 'public';
      securityLevel?: 'standard' | 'high';
      additionalChecks?: (
        data: any,
        context?: OAuthValidationContext
      ) => boolean | Promise<boolean>;
      errorMessage?: string;
      errorCode?: string;
    }
  ) => {
    const { additionalChecks, errorMessage, errorCode } = options || {};

    // Apply different validation rules based on client type and security level
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
