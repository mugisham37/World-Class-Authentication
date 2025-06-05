/**
 * SSO event types
 */
export enum SSOEvent {
  // SAML events
  SAML_REQUEST_GENERATED = 'sso.saml.request_generated',
  SAML_RESPONSE_RECEIVED = 'sso.saml.response_received',
  SAML_ASSERTION_VALIDATED = 'sso.saml.assertion_validated',
  SAML_ASSERTION_INVALID = 'sso.saml.assertion_invalid',
  SAML_LOGOUT_REQUEST_GENERATED = 'sso.saml.logout_request_generated',
  SAML_LOGOUT_RESPONSE_RECEIVED = 'sso.saml.logout_response_received',

  // Identity Provider events
  IDP_ADDED = 'sso.idp.added',
  IDP_UPDATED = 'sso.idp.updated',
  IDP_REMOVED = 'sso.idp.removed',
  IDP_ENABLED = 'sso.idp.enabled',
  IDP_DISABLED = 'sso.idp.disabled',

  // User provisioning events
  USER_PROVISIONED = 'sso.user.provisioned',
  USER_LINKED = 'sso.user.linked',
  USER_UNLINKED = 'sso.user.unlinked',

  // Session events
  SSO_SESSION_CREATED = 'sso.session.created',
  SSO_SESSION_VALIDATED = 'sso.session.validated',
  SSO_SESSION_EXPIRED = 'sso.session.expired',
  SSO_SESSION_TERMINATED = 'sso.session.terminated',

  // Error events
  INVALID_SAML_REQUEST = 'sso.error.invalid_saml_request',
  INVALID_SAML_RESPONSE = 'sso.error.invalid_saml_response',
  INVALID_SIGNATURE = 'sso.error.invalid_signature',
  INVALID_CERTIFICATE = 'sso.error.invalid_certificate',
  UNKNOWN_IDP = 'sso.error.unknown_idp',
  PROVISIONING_ERROR = 'sso.error.provisioning_error',
}

/**
 * SSO event payload interface
 */
export interface SSOEventPayload {
  timestamp: Date;
  idpId?: string;
  idpName?: string;
  userId?: string;
  sessionId?: string;
  requestId?: string;
  entityId?: string;
  assertionId?: string;
  nameId?: string;
  nameIdFormat?: string;
  authnContext?: string;
  relayState?: string;
  error?: string;
  errorDescription?: string;
  ip?: string;
  userAgent?: string;
  metadata?: Record<string, any>;
}

/**
 * SAML user interface
 */
export interface SAMLUser {
  nameId: string;
  nameIdFormat: string;
  sessionIndex?: string;
  attributes: Record<string, string[]>;
  authnContext?: string;
  issuer: string;
  assertionId: string;
  assertionIssueInstant: Date;
  assertionNotBefore?: Date;
  assertionNotOnOrAfter?: Date;
}

/**
 * SAML request interface
 */
export interface SAMLRequest {
  id: string;
  destination: string;
  issuer: string;
  acsUrl: string;
  forceAuthn?: boolean;
  isPassive?: boolean;
  relayState?: string;
  requestedAuthnContext?: string[];
  requestXml: string;
  encodedRequest: string;
}

/**
 * SAML response interface
 */
export interface SAMLResponse {
  id: string;
  inResponseTo?: string;
  destination?: string;
  issuer: string;
  status: {
    code: string;
    subCode?: string;
    message?: string;
  };
  assertion?: SAMLUser;
  responseXml: string;
}

/**
 * SAML logout request interface
 */
export interface SAMLLogoutRequest {
  id: string;
  destination: string;
  issuer: string;
  nameId: string;
  nameIdFormat: string;
  sessionIndex?: string;
  reason?: string;
  notOnOrAfter?: Date;
  requestXml: string;
  encodedRequest: string;
}

/**
 * SAML logout response interface
 */
export interface SAMLLogoutResponse {
  id: string;
  inResponseTo: string;
  destination: string;
  issuer: string;
  status: {
    code: string;
    subCode?: string;
    message?: string;
  };
  responseXml: string;
}

/**
 * Identity provider metadata interface
 */
export interface IdPMetadata {
  entityId: string;
  ssoUrl: string;
  sloUrl?: string;
  certificates: string[];
  nameIdFormats?: string[];
  wantAuthnRequestsSigned?: boolean;
  wantAssertionsSigned?: boolean;
  signatureAlgorithm?: string;
  digestAlgorithm?: string;
  supportedBindings?: string[];
}

/**
 * Identity provider configuration interface
 */
export interface IdPConfiguration {
  id?: string;
  name: string;
  description?: string;
  entityId: string;
  ssoUrl: string;
  sloUrl?: string;
  certificate: string;
  attributeMapping: AttributeMapping;
  nameIdFormat?: string;
  signatureAlgorithm?: string;
  digestAlgorithm?: string;
  authnContextClassRef?: string;
  forceAuthn?: boolean;
  isPassive?: boolean;
  jitProvisioning: boolean;
  isActive: boolean;
  createdAt?: Date;
  updatedAt?: Date;
}

/**
 * Attribute mapping interface
 */
export interface AttributeMapping {
  id?: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  displayName?: string;
  username?: string;
  groups?: string;
  roles?: string;
  [key: string]: string | undefined;
}

/**
 * SSO session interface
 */
export interface SSOSession {
  id: string;
  userId: string;
  idpId: string;
  sessionIndex?: string;
  nameId: string;
  nameIdFormat: string;
  attributes: Record<string, string[]>;
  authnContext?: string;
  issuer: string;
  createdAt: Date;
  expiresAt?: Date;
  lastValidatedAt?: Date;
}
