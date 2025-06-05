import dotenv from 'dotenv';
import path from 'path';
import { validateConfig } from '../utils/validation';
import { z } from 'zod';

// Load environment variables from .env file
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

// Define SAML config schema with Zod
const samlConfigSchema = z.object({
  enabled: z.boolean().default(true),
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
  session: z.object({
    expirationInSeconds: z.number().int().positive().default(86400), // 24 hours
    cookieName: z.string().default('saml_session'),
    cookieSecure: z.boolean().default(true),
    cookieHttpOnly: z.boolean().default(true),
    cookieSameSite: z.enum(['strict', 'lax', 'none']).default('lax'),
    cookieDomain: z.string().optional(),
    cookiePath: z.string().default('/'),
  }),
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
  enabled: process.env.SAML_ENABLED === 'true',
  serviceProvider: {
    entityId: process.env.SAML_SP_ENTITY_ID,
    assertionConsumerServiceUrl: process.env.SAML_SP_ACS_URL,
    singleLogoutServiceUrl: process.env.SAML_SP_SLO_URL,
    attributeConsumingServiceIndex: process.env.SAML_SP_ACS_INDEX
      ? parseInt(process.env.SAML_SP_ACS_INDEX)
      : undefined,
    authnRequestsSigned: process.env.SAML_SP_AUTHN_REQUESTS_SIGNED !== 'false',
    wantAssertionsSigned: process.env.SAML_SP_WANT_ASSERTIONS_SIGNED !== 'false',
    signatureAlgorithm: process.env.SAML_SP_SIGNATURE_ALGORITHM,
    digestAlgorithm: process.env.SAML_SP_DIGEST_ALGORITHM,
    metadataUrl: process.env.SAML_SP_METADATA_URL,
    nameIdFormat: process.env.SAML_SP_NAME_ID_FORMAT,
    privateKey: process.env.SAML_SP_PRIVATE_KEY,
    privateKeyPath: process.env.SAML_SP_PRIVATE_KEY_PATH,
    certificate: process.env.SAML_SP_CERTIFICATE,
    certificatePath: process.env.SAML_SP_CERTIFICATE_PATH,
    decryptionPvk: process.env.SAML_SP_DECRYPTION_PVK,
    decryptionCert: process.env.SAML_SP_DECRYPTION_CERT,
  },
  identityProviders: process.env.SAML_IDP_CONFIG ? JSON.parse(process.env.SAML_IDP_CONFIG) : [],
  session: {
    expirationInSeconds: process.env.SAML_SESSION_EXPIRATION
      ? parseInt(process.env.SAML_SESSION_EXPIRATION)
      : undefined,
    cookieName: process.env.SAML_SESSION_COOKIE_NAME,
    cookieSecure: process.env.SAML_SESSION_COOKIE_SECURE !== 'false',
    cookieHttpOnly: process.env.SAML_SESSION_COOKIE_HTTP_ONLY !== 'false',
    cookieSameSite: process.env.SAML_SESSION_COOKIE_SAME_SITE as 'strict' | 'lax' | 'none',
    cookieDomain: process.env.SAML_SESSION_COOKIE_DOMAIN,
    cookiePath: process.env.SAML_SESSION_COOKIE_PATH,
  },
  userProvisioning: {
    enabled: process.env.SAML_USER_PROVISIONING_ENABLED !== 'false',
    defaultRole: process.env.SAML_USER_PROVISIONING_DEFAULT_ROLE,
    allowedDomains: process.env.SAML_USER_PROVISIONING_ALLOWED_DOMAINS
      ? process.env.SAML_USER_PROVISIONING_ALLOWED_DOMAINS.split(',')
      : [],
    attributeMapping: {
      email: process.env.SAML_USER_PROVISIONING_ATTR_EMAIL,
      firstName: process.env.SAML_USER_PROVISIONING_ATTR_FIRST_NAME,
      lastName: process.env.SAML_USER_PROVISIONING_ATTR_LAST_NAME,
      displayName: process.env.SAML_USER_PROVISIONING_ATTR_DISPLAY_NAME,
      username: process.env.SAML_USER_PROVISIONING_ATTR_USERNAME,
      groups: process.env.SAML_USER_PROVISIONING_ATTR_GROUPS,
      roles: process.env.SAML_USER_PROVISIONING_ATTR_ROLES,
    },
    groupMapping: process.env.SAML_USER_PROVISIONING_GROUP_MAPPING
      ? JSON.parse(process.env.SAML_USER_PROVISIONING_GROUP_MAPPING)
      : {},
  },
  security: {
    requestMaxAgeInSeconds: process.env.SAML_SECURITY_REQUEST_MAX_AGE
      ? parseInt(process.env.SAML_SECURITY_REQUEST_MAX_AGE)
      : undefined,
    responseValidityInSeconds: process.env.SAML_SECURITY_RESPONSE_VALIDITY
      ? parseInt(process.env.SAML_SECURITY_RESPONSE_VALIDITY)
      : undefined,
    allowedClockSkewInSeconds: process.env.SAML_SECURITY_ALLOWED_CLOCK_SKEW
      ? parseInt(process.env.SAML_SECURITY_ALLOWED_CLOCK_SKEW)
      : undefined,
    replayDetection: process.env.SAML_SECURITY_REPLAY_DETECTION !== 'false',
    validateInResponseTo: process.env.SAML_SECURITY_VALIDATE_IN_RESPONSE_TO !== 'false',
    validateDestination: process.env.SAML_SECURITY_VALIDATE_DESTINATION !== 'false',
    validateAudience: process.env.SAML_SECURITY_VALIDATE_AUDIENCE !== 'false',
    validateSignature: process.env.SAML_SECURITY_VALIDATE_SIGNATURE !== 'false',
    validateLifetime: process.env.SAML_SECURITY_VALIDATE_LIFETIME !== 'false',
  },
  logging: {
    enabled: process.env.SAML_LOGGING_ENABLED !== 'false',
    logSamlRequests: process.env.SAML_LOGGING_REQUESTS !== 'false',
    logSamlResponses: process.env.SAML_LOGGING_RESPONSES !== 'false',
    logDecryptedAssertions: process.env.SAML_LOGGING_DECRYPTED_ASSERTIONS === 'true',
    logLevel: process.env.SAML_LOGGING_LEVEL as 'error' | 'warn' | 'info' | 'debug',
  },
};

// Validate and export config
export const samlConfig = validateConfig(samlConfigSchema, rawConfig);

// Export config type
export type SAMLConfig = typeof samlConfig;
