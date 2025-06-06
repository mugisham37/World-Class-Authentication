import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define SAML config schema with Zod
const samlConfigSchema = z.object({
  // General settings
  enabled: z.boolean().default(true),
  defaultEntityId: z.string().default('urn:auth-system:idp'),
  requestTtl: z.number().int().positive().default(300), // 5 minutes
  assertionTtl: z.number().int().positive().default(300), // 5 minutes
  sessionTtl: z.number().int().positive().default(86400), // 24 hours
  signatureAlgorithm: z.string().default('sha256'),
  digestAlgorithm: z.string().default('sha256'),
  defaultNameIdFormat: z.string().default('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'),
  defaultBinding: z.string().default('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),

  // Validation settings
  allowUnsolicitedResponses: z.boolean().default(false),
  validateAudienceRestriction: z.boolean().default(true),
  validateDestination: z.boolean().default(true),
  validateIssuer: z.boolean().default(true),
  validateSignature: z.boolean().default(true),
  validateLifetime: z.boolean().default(true),
  clockSkew: z.number().int().nonnegative().default(60), // 60 seconds

  // Service provider settings
  serviceProvider: z.object({
    entityId: z.string().default('https://auth.example.com'),
    assertionConsumerServiceUrl: z.string().default('https://auth.example.com/saml/acs'),
    singleLogoutServiceUrl: z.string().default('https://auth.example.com/saml/slo'),
    attributeConsumingServiceIndex: z.number().int().optional(),
    authnRequestsSigned: z.boolean().default(true),
    wantAssertionsSigned: z.boolean().default(true),
    signatureAlgorithm: z.string().default('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'),
    digestAlgorithm: z.string().default('http://www.w3.org/2001/04/xmlenc#sha256'),
    metadataUrl: z.string().default('https://auth.example.com/saml/metadata'),
    nameIdFormat: z.string().default('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'),
    privateKey: z.string().optional(),
    privateKeyPath: z.string().optional(),
    certificate: z.string().optional(),
    certificatePath: z.string().optional(),
    decryptionPvk: z.string().optional(),
    decryptionCert: z.string().optional(),
  }),

  // Service providers (for IdP role)
  serviceProviders: z
    .array(
      z.object({
        entityId: z.string(),
        assertionConsumerServiceUrl: z.string().url(),
        nameIdFormat: z.string().optional(),
        binding: z.string().optional(),
        signingCertificate: z.string().optional(),
        encryptionCertificate: z.string().optional(),
        enabled: z.boolean().default(true),
      })
    )
    .default([]),

  // Identity providers
  identityProviders: z
    .array(
      z.object({
        id: z.string(),
        name: z.string(),
        entityId: z.string(),
        ssoUrl: z.string(),
        sloUrl: z.string().optional(),
        certificate: z.string(),
        certificatePath: z.string().optional(),
        wantAuthnRequestsSigned: z.boolean().default(true),
        wantAssertionsSigned: z.boolean().default(true),
        signatureAlgorithm: z.string().default('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'),
        digestAlgorithm: z.string().default('http://www.w3.org/2001/04/xmlenc#sha256'),
        nameIdFormat: z.string().default('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'),
        attributeMapping: z.record(z.string()).default({}),
        allowUnencryptedAssertions: z.boolean().default(true),
        disableRequestedAuthnContext: z.boolean().default(false),
        authnContext: z.string().optional(),
        forceAuthn: z.boolean().default(false),
        isPassive: z.boolean().default(false),
        isActive: z.boolean().default(true),
        jitProvisioning: z.boolean().default(true),
      })
    )
    .default([]),

  // Session settings
  session: z.object({
    expirationInSeconds: z.number().int().positive().default(86400), // 24 hours
    cookieName: z.string().default('saml_session'),
    cookieSecure: z.boolean().default(true),
    cookieHttpOnly: z.boolean().default(true),
    cookieSameSite: z.enum(['strict', 'lax', 'none']).default('lax'),
    cookieDomain: z.string().optional(),
    cookiePath: z.string().default('/'),
  }),

  // User provisioning settings
  userProvisioning: z.object({
    enabled: z.boolean().default(true),
    defaultRole: z.string().default('user'),
    allowedDomains: z.array(z.string()).default([]),
    attributeMapping: z.object({
      email: z.string().default('email'),
      firstName: z.string().default('firstName'),
      lastName: z.string().default('lastName'),
      displayName: z.string().default('displayName'),
      username: z.string().default('username'),
      groups: z.string().default('groups'),
      roles: z.string().default('roles'),
    }),
    groupMapping: z.record(z.array(z.string())).default({}),
  }),

  // Security settings
  security: z.object({
    requestMaxAgeInSeconds: z.number().int().positive().default(300), // 5 minutes
    responseValidityInSeconds: z.number().int().positive().default(300), // 5 minutes
    allowedClockSkewInSeconds: z.number().int().nonnegative().default(30),
    replayDetection: z.boolean().default(true),
    validateInResponseTo: z.boolean().default(true),
    validateDestination: z.boolean().default(true),
    validateAudience: z.boolean().default(true),
    validateSignature: z.boolean().default(true),
    validateLifetime: z.boolean().default(true),
  }),

  // Logging settings
  logging: z.object({
    enabled: z.boolean().default(true),
    logSamlRequests: z.boolean().default(true),
    logSamlResponses: z.boolean().default(true),
    logDecryptedAssertions: z.boolean().default(false),
    logLevel: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  }),
});

// Parse and validate environment variables
const rawConfig = {
  // General settings
  enabled: env.getBoolean('SAML_ENABLED', true),
  defaultEntityId: env.get('SAML_DEFAULT_ENTITY_ID', 'urn:auth-system:idp'),
  requestTtl: env.getNumber('SAML_REQUEST_TTL', 300),
  assertionTtl: env.getNumber('SAML_ASSERTION_TTL', 300),
  sessionTtl: env.getNumber('SAML_SESSION_TTL', 86400),
  signatureAlgorithm: env.get('SAML_SIGNATURE_ALGORITHM', 'sha256'),
  digestAlgorithm: env.get('SAML_DIGEST_ALGORITHM', 'sha256'),
  defaultNameIdFormat: env.get(
    'SAML_DEFAULT_NAME_ID_FORMAT',
    'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
  ),
  defaultBinding: env.get('SAML_DEFAULT_BINDING', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),

  // Validation settings
  allowUnsolicitedResponses: env.getBoolean('SAML_ALLOW_UNSOLICITED_RESPONSES', false),
  validateAudienceRestriction: env.getBoolean('SAML_VALIDATE_AUDIENCE_RESTRICTION', true),
  validateDestination: env.getBoolean('SAML_VALIDATE_DESTINATION', true),
  validateIssuer: env.getBoolean('SAML_VALIDATE_ISSUER', true),
  validateSignature: env.getBoolean('SAML_VALIDATE_SIGNATURE', true),
  validateLifetime: env.getBoolean('SAML_VALIDATE_LIFETIME', true),
  clockSkew: env.getNumber('SAML_CLOCK_SKEW', 60),

  // Service provider settings
  serviceProvider: {
    entityId: env.get('SAML_SP_ENTITY_ID', 'https://auth.example.com'),
    assertionConsumerServiceUrl: env.get('SAML_SP_ACS_URL', 'https://auth.example.com/saml/acs'),
    singleLogoutServiceUrl: env.get('SAML_SP_SLO_URL', 'https://auth.example.com/saml/slo'),
    attributeConsumingServiceIndex: env.getNumber('SAML_SP_ACS_INDEX'),
    authnRequestsSigned: env.getBoolean('SAML_SP_AUTHN_REQUESTS_SIGNED', true),
    wantAssertionsSigned: env.getBoolean('SAML_SP_WANT_ASSERTIONS_SIGNED', true),
    signatureAlgorithm: env.get(
      'SAML_SP_SIGNATURE_ALGORITHM',
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
    ),
    digestAlgorithm: env.get('SAML_SP_DIGEST_ALGORITHM', 'http://www.w3.org/2001/04/xmlenc#sha256'),
    metadataUrl: env.get('SAML_SP_METADATA_URL', 'https://auth.example.com/saml/metadata'),
    nameIdFormat: env.get(
      'SAML_SP_NAME_ID_FORMAT',
      'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    ),
    privateKey: env.get('SAML_SP_PRIVATE_KEY'),
    privateKeyPath: env.get('SAML_SP_PRIVATE_KEY_PATH'),
    certificate: env.get('SAML_SP_CERTIFICATE'),
    certificatePath: env.get('SAML_SP_CERTIFICATE_PATH'),
    decryptionPvk: env.get('SAML_SP_DECRYPTION_PVK'),
    decryptionCert: env.get('SAML_SP_DECRYPTION_CERT'),
  },

  // Service providers (for IdP role)
  serviceProviders: env.get('SAML_SERVICE_PROVIDERS')
    ? JSON.parse(env.get('SAML_SERVICE_PROVIDERS') as string)
    : [],

  // Identity providers
  identityProviders: env.get('SAML_IDP_CONFIG')
    ? JSON.parse(env.get('SAML_IDP_CONFIG') as string)
    : [],

  // Session settings
  session: {
    expirationInSeconds: env.getNumber('SAML_SESSION_EXPIRATION', 86400),
    cookieName: env.get('SAML_SESSION_COOKIE_NAME', 'saml_session'),
    cookieSecure: env.getBoolean('SAML_SESSION_COOKIE_SECURE', true),
    cookieHttpOnly: env.getBoolean('SAML_SESSION_COOKIE_HTTP_ONLY', true),
    cookieSameSite: env.get('SAML_SESSION_COOKIE_SAME_SITE', 'lax') as 'strict' | 'lax' | 'none',
    cookieDomain: env.get('SAML_SESSION_COOKIE_DOMAIN'),
    cookiePath: env.get('SAML_SESSION_COOKIE_PATH', '/'),
  },

  // User provisioning settings
  userProvisioning: {
    enabled: env.getBoolean('SAML_USER_PROVISIONING_ENABLED', true),
    defaultRole: env.get('SAML_USER_PROVISIONING_DEFAULT_ROLE', 'user'),
    allowedDomains: env.get('SAML_USER_PROVISIONING_ALLOWED_DOMAINS')
      ? env.get('SAML_USER_PROVISIONING_ALLOWED_DOMAINS')!.split(',')
      : [],
    attributeMapping: {
      email: env.get('SAML_USER_PROVISIONING_ATTR_EMAIL', 'email'),
      firstName: env.get('SAML_USER_PROVISIONING_ATTR_FIRST_NAME', 'firstName'),
      lastName: env.get('SAML_USER_PROVISIONING_ATTR_LAST_NAME', 'lastName'),
      displayName: env.get('SAML_USER_PROVISIONING_ATTR_DISPLAY_NAME', 'displayName'),
      username: env.get('SAML_USER_PROVISIONING_ATTR_USERNAME', 'username'),
      groups: env.get('SAML_USER_PROVISIONING_ATTR_GROUPS', 'groups'),
      roles: env.get('SAML_USER_PROVISIONING_ATTR_ROLES', 'roles'),
    },
    groupMapping: env.get('SAML_USER_PROVISIONING_GROUP_MAPPING')
      ? JSON.parse(env.get('SAML_USER_PROVISIONING_GROUP_MAPPING') as string)
      : {},
  },

  // Security settings
  security: {
    requestMaxAgeInSeconds: env.getNumber('SAML_SECURITY_REQUEST_MAX_AGE', 300),
    responseValidityInSeconds: env.getNumber('SAML_SECURITY_RESPONSE_VALIDITY', 300),
    allowedClockSkewInSeconds: env.getNumber('SAML_SECURITY_ALLOWED_CLOCK_SKEW', 30),
    replayDetection: env.getBoolean('SAML_SECURITY_REPLAY_DETECTION', true),
    validateInResponseTo: env.getBoolean('SAML_SECURITY_VALIDATE_IN_RESPONSE_TO', true),
    validateDestination: env.getBoolean('SAML_SECURITY_VALIDATE_DESTINATION', true),
    validateAudience: env.getBoolean('SAML_SECURITY_VALIDATE_AUDIENCE', true),
    validateSignature: env.getBoolean('SAML_SECURITY_VALIDATE_SIGNATURE', true),
    validateLifetime: env.getBoolean('SAML_SECURITY_VALIDATE_LIFETIME', true),
  },

  // Logging settings
  logging: {
    enabled: env.getBoolean('SAML_LOGGING_ENABLED', true),
    logSamlRequests: env.getBoolean('SAML_LOGGING_REQUESTS', true),
    logSamlResponses: env.getBoolean('SAML_LOGGING_RESPONSES', true),
    logDecryptedAssertions: env.getBoolean('SAML_LOGGING_DECRYPTED_ASSERTIONS', false),
    logLevel: env.get('SAML_LOGGING_LEVEL', 'info') as 'error' | 'warn' | 'info' | 'debug',
  },
};

// Validate and export config
export const samlConfig = validateConfig(samlConfigSchema, rawConfig);

// Export config type
export type SamlConfig = typeof samlConfig;
