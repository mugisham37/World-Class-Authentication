import { env } from './environment';

/**
 * SAML Environment Variables Helper
 * Provides typed access to SAML-related environment variables
 */
export const samlEnv = {
  // Core SAML settings
  enabled: () => env.getBoolean('SAML_ENABLED', true),
  
  // Service Provider settings
  serviceProvider: {
    entityId: () => env.get('SAML_SP_ENTITY_ID', 'https://auth.example.com'),
    acsUrl: () => env.get('SAML_SP_ACS_URL', 'https://auth.example.com/saml/acs'),
    sloUrl: () => env.get('SAML_SP_SLO_URL', 'https://auth.example.com/saml/slo'),
    acsIndex: () => {
      const value = env.get('SAML_SP_ACS_INDEX');
      return value ? parseInt(value, 10) : undefined;
    },
    authnRequestsSigned: () => env.getBoolean('SAML_SP_AUTHN_REQUESTS_SIGNED', true),
    wantAssertionsSigned: () => env.getBoolean('SAML_SP_WANT_ASSERTIONS_SIGNED', true),
    signatureAlgorithm: () => env.get('SAML_SP_SIGNATURE_ALGORITHM', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'),
    digestAlgorithm: () => env.get('SAML_SP_DIGEST_ALGORITHM', 'http://www.w3.org/2001/04/xmlenc#sha256'),
    metadataUrl: () => env.get('SAML_SP_METADATA_URL', 'https://auth.example.com/saml/metadata'),
    nameIdFormat: () => env.get('SAML_SP_NAME_ID_FORMAT', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'),
    privateKey: () => env.get('SAML_SP_PRIVATE_KEY'),
    privateKeyPath: () => env.get('SAML_SP_PRIVATE_KEY_PATH'),
    certificate: () => env.get('SAML_SP_CERTIFICATE'),
    certificatePath: () => env.get('SAML_SP_CERTIFICATE_PATH'),
    decryptionPvk: () => env.get('SAML_SP_DECRYPTION_PVK'),
    decryptionCert: () => env.get('SAML_SP_DECRYPTION_CERT'),
  },
  
  // Identity Provider settings
  identityProviders: () => {
    const idpConfig = env.get('SAML_IDP_CONFIG');
    return idpConfig ? JSON.parse(idpConfig) : [];
  },
  
  // Session settings
  session: {
    expirationInSeconds: () => {
      const value = env.get('SAML_SESSION_EXPIRATION');
      return value ? parseInt(value, 10) : 86400; // 24 hours default
    },
    cookieName: () => env.get('SAML_SESSION_COOKIE_NAME', 'saml_session'),
    cookieSecure: () => env.getBoolean('SAML_SESSION_COOKIE_SECURE', true),
    cookieHttpOnly: () => env.getBoolean('SAML_SESSION_COOKIE_HTTP_ONLY', true),
    cookieSameSite: () => env.get('SAML_SESSION_COOKIE_SAME_SITE', 'lax') as 'strict' | 'lax' | 'none',
    cookieDomain: () => env.get('SAML_SESSION_COOKIE_DOMAIN'),
    cookiePath: () => env.get('SAML_SESSION_COOKIE_PATH', '/'),
  },
  
  // User Provisioning settings
  userProvisioning: {
    enabled: () => env.getBoolean('SAML_USER_PROVISIONING_ENABLED', true),
    defaultRole: () => env.get('SAML_USER_PROVISIONING_DEFAULT_ROLE', 'user'),
    allowedDomains: () => {
      const domains = env.get('SAML_USER_PROVISIONING_ALLOWED_DOMAINS');
      return domains ? domains.split(',') : [];
    },
    attributeMapping: {
      email: () => env.get('SAML_USER_PROVISIONING_ATTR_EMAIL', 'email'),
      firstName: () => env.get('SAML_USER_PROVISIONING_ATTR_FIRST_NAME', 'firstName'),
      lastName: () => env.get('SAML_USER_PROVISIONING_ATTR_LAST_NAME', 'lastName'),
      displayName: () => env.get('SAML_USER_PROVISIONING_ATTR_DISPLAY_NAME', 'displayName'),
      username: () => env.get('SAML_USER_PROVISIONING_ATTR_USERNAME', 'username'),
      groups: () => env.get('SAML_USER_PROVISIONING_ATTR_GROUPS', 'groups'),
      roles: () => env.get('SAML_USER_PROVISIONING_ATTR_ROLES', 'roles'),
    },
    groupMapping: () => {
      const mapping = env.get('SAML_USER_PROVISIONING_GROUP_MAPPING');
      return mapping ? JSON.parse(mapping) : {};
    },
  },
  
  // Security settings
  security: {
    requestMaxAgeInSeconds: () => {
      const value = env.get('SAML_SECURITY_REQUEST_MAX_AGE');
      return value ? parseInt(value, 10) : 300; // 5 minutes default
    },
    responseValidityInSeconds: () => {
      const value = env.get('SAML_SECURITY_RESPONSE_VALIDITY');
      return value ? parseInt(value, 10) : 300; // 5 minutes default
    },
    allowedClockSkewInSeconds: () => {
      const value = env.get('SAML_SECURITY_ALLOWED_CLOCK_SKEW');
      return value ? parseInt(value, 10) : 30; // 30 seconds default
    },
    replayDetection: () => env.getBoolean('SAML_SECURITY_REPLAY_DETECTION', true),
    validateInResponseTo: () => env.getBoolean('SAML_SECURITY_VALIDATE_IN_RESPONSE_TO', true),
    validateDestination: () => env.getBoolean('SAML_SECURITY_VALIDATE_DESTINATION', true),
    validateAudience: () => env.getBoolean('SAML_SECURITY_VALIDATE_AUDIENCE', true),
    validateSignature: () => env.getBoolean('SAML_SECURITY_VALIDATE_SIGNATURE', true),
    validateLifetime: () => env.getBoolean('SAML_SECURITY_VALIDATE_LIFETIME', true),
  },
  
  // Logging settings
  logging: {
    enabled: () => env.getBoolean('SAML_LOGGING_ENABLED', true),
    logSamlRequests: () => env.getBoolean('SAML_LOGGING_REQUESTS', true),
    logSamlResponses: () => env.getBoolean('SAML_LOGGING_RESPONSES', true),
    logDecryptedAssertions: () => env.getBoolean('SAML_LOGGING_DECRYPTED_ASSERTIONS', false),
    logLevel: () => env.get('SAML_LOGGING_LEVEL', 'info') as 'error' | 'warn' | 'info' | 'debug',
  },
};
