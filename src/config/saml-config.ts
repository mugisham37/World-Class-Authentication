import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define SAML config schema with Zod
const samlConfigSchema = z.object({
  defaultEntityId: z.string().default('urn:auth-system:idp'),
  requestTtl: z.number().int().positive().default(300), // 5 minutes
  assertionTtl: z.number().int().positive().default(300), // 5 minutes
  sessionTtl: z.number().int().positive().default(86400), // 24 hours
  signatureAlgorithm: z.string().default('sha256'),
  digestAlgorithm: z.string().default('sha256'),
  defaultNameIdFormat: z.string().default('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'),
  defaultBinding: z.string().default('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
  allowUnsolicitedResponses: z.boolean().default(false),
  validateAudienceRestriction: z.boolean().default(true),
  validateDestination: z.boolean().default(true),
  validateIssuer: z.boolean().default(true),
  validateSignature: z.boolean().default(true),
  validateLifetime: z.boolean().default(true),
  clockSkew: z.number().int().nonnegative().default(60), // 60 seconds
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
});

// Parse and validate environment variables
const rawConfig = {
  defaultEntityId: env.get('SAML_DEFAULT_ENTITY_ID'),
  requestTtl: env.getNumber('SAML_REQUEST_TTL'),
  assertionTtl: env.getNumber('SAML_ASSERTION_TTL'),
  sessionTtl: env.getNumber('SAML_SESSION_TTL'),
  signatureAlgorithm: env.get('SAML_SIGNATURE_ALGORITHM'),
  digestAlgorithm: env.get('SAML_DIGEST_ALGORITHM'),
  defaultNameIdFormat: env.get('SAML_DEFAULT_NAME_ID_FORMAT'),
  defaultBinding: env.get('SAML_DEFAULT_BINDING'),
  allowUnsolicitedResponses: env.getBoolean('SAML_ALLOW_UNSOLICITED_RESPONSES'),
  validateAudienceRestriction: env.getBoolean('SAML_VALIDATE_AUDIENCE_RESTRICTION'),
  validateDestination: env.getBoolean('SAML_VALIDATE_DESTINATION'),
  validateIssuer: env.getBoolean('SAML_VALIDATE_ISSUER'),
  validateSignature: env.getBoolean('SAML_VALIDATE_SIGNATURE'),
  validateLifetime: env.getBoolean('SAML_VALIDATE_LIFETIME'),
  clockSkew: env.getNumber('SAML_CLOCK_SKEW'),
  serviceProviders: env.get('SAML_SERVICE_PROVIDERS')
    ? JSON.parse(env.get('SAML_SERVICE_PROVIDERS') as string)
    : [],
};

// Validate and export config
export const samlConfig = validateConfig(samlConfigSchema, rawConfig);

// Export config type
export type SamlConfig = typeof samlConfig;
