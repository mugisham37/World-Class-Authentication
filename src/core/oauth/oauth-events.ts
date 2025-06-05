/**
 * OAuth event types
 */
export enum OAuthEvent {
  // Client events
  CLIENT_CREATED = "oauth.client.created",
  CLIENT_UPDATED = "oauth.client.updated",
  CLIENT_DELETED = "oauth.client.deleted",
  CLIENT_SECRET_REGENERATED = "oauth.client.secret_regenerated",
  
  // Token events
  TOKEN_ISSUED = "oauth.token.issued",
  TOKEN_REFRESHED = "oauth.token.refreshed",
  TOKEN_REVOKED = "oauth.token.revoked",
  TOKEN_VALIDATED = "oauth.token.validated",
  TOKEN_EXPIRED = "oauth.token.expired",
  TOKEN_INTROSPECTED = "oauth.token.introspected",
  
  // Authorization events
  AUTHORIZATION_CODE_GENERATED = "oauth.authorization.code_generated",
  AUTHORIZATION_GRANTED = "oauth.authorization.granted",
  AUTHORIZATION_DENIED = "oauth.authorization.denied",
  
  // Consent events
  CONSENT_GRANTED = "oauth.consent.granted",
  CONSENT_REVOKED = "oauth.consent.revoked",
  CONSENT_UPDATED = "oauth.consent.updated",
  
  // Scope events
  SCOPE_CREATED = "oauth.scope.created",
  SCOPE_UPDATED = "oauth.scope.updated",
  SCOPE_DELETED = "oauth.scope.deleted",
  
  // Error events
  INVALID_CLIENT = "oauth.error.invalid_client",
  INVALID_GRANT = "oauth.error.invalid_grant",
  INVALID_REQUEST = "oauth.error.invalid_request",
  INVALID_SCOPE = "oauth.error.invalid_scope",
  INVALID_TOKEN = "oauth.error.invalid_token",
  UNAUTHORIZED_CLIENT = "oauth.error.unauthorized_client",
  UNSUPPORTED_GRANT_TYPE = "oauth.error.unsupported_grant_type",
  UNSUPPORTED_RESPONSE_TYPE = "oauth.error.unsupported_response_type",
  SERVER_ERROR = "oauth.error.server_error",
}

/**
 * OAuth event payload interface
 */
export interface OAuthEventPayload {
  timestamp: Date;
  clientId?: string;
  clientName?: string;
  userId?: string;
  tokenId?: string;
  scope?: string;
  grantType?: string;
  responseType?: string;
  error?: string;
  errorDescription?: string;
  ip?: string;
  userAgent?: string;
  metadata?: Record<string, any>;
}
