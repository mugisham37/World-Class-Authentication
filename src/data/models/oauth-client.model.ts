/**
 * OAuth client model interface
 * Represents an OAuth client in the system
 */
export interface OAuthClient {
  id: string;
  userId: string;
  clientId: string;
  clientSecret: string;
  name: string;
  description?: string | null;
  redirectUris: string[];
  allowedGrantTypes: string[];
  allowedScopes: string[];
  defaultScopes: string[];
  clientType: string;
  authMethod: string;
  requirePkce: boolean;
  requireUserConsent: boolean;
  isFirstParty: boolean;
  isActive: boolean;
  jwksUri?: string | null;
  jwks?: Record<string, any> | null;
  logoUri?: string | null;
  policyUri?: string | null;
  tosUri?: string | null;
  contacts: string[];
  subjectType: string;
  idTokenSignedResponseAlg: string;
  idTokenEncryptedResponseAlg?: string | null;
  idTokenEncryptedResponseEnc?: string | null;
  userinfoSignedResponseAlg?: string | null;
  userinfoEncryptedResponseAlg?: string | null;
  userinfoEncryptedResponseEnc?: string | null;
  requestObjectSigningAlg?: string | null;
  requestObjectEncryptionAlg?: string | null;
  requestObjectEncryptionEnc?: string | null;
  tokenEndpointAuthSigningAlg?: string | null;
  defaultMaxAge?: number | null;
  requireAuthTime: boolean;
  defaultAcrValues: string[];
  initiateLoginUri?: string | null;
  softwareId?: string | null;
  softwareVersion?: string | null;
  createdAt: Date;
  updatedAt: Date;
  metadata?: Record<string, any> | null;
}

/**
 * Create OAuth client data interface
 * Represents the data needed to create a new OAuth client
 */
export interface CreateOAuthClientData {
  id?: string;
  userId: string;
  clientId: string;
  clientSecret: string;
  secret?: string;
  name: string;
  description?: string | null;
  redirectUris?: string[];
  allowedGrantTypes?: string[];
  allowedScopes?: string[];
  defaultScopes?: string[];
  allowedResponseTypes?: string[];
  clientType: string;
  authMethod: string;
  requirePkce?: boolean;
  requireUserConsent?: boolean;
  isFirstParty?: boolean;
  isActive?: boolean;
  jwksUri?: string | null;
  jwks?: Record<string, any> | null;
  logoUri?: string | null;
  policyUri?: string | null;
  tosUri?: string | null;
  contacts?: string[];
  subjectType?: string;
  idTokenSignedResponseAlg?: string;
  idTokenEncryptedResponseAlg?: string | null;
  idTokenEncryptedResponseEnc?: string | null;
  userinfoSignedResponseAlg?: string | null;
  userinfoEncryptedResponseAlg?: string | null;
  userinfoEncryptedResponseEnc?: string | null;
  requestObjectSigningAlg?: string | null;
  requestObjectEncryptionAlg?: string | null;
  requestObjectEncryptionEnc?: string | null;
  tokenEndpointAuthSigningAlg?: string | null;
  defaultMaxAge?: number | null;
  requireAuthTime?: boolean;
  defaultAcrValues?: string[];
  initiateLoginUri?: string | null;
  softwareId?: string | null;
  softwareVersion?: string | null;
  metadata?: Record<string, any> | null;
}

/**
 * Update OAuth client data interface
 * Represents the data needed to update an existing OAuth client
 */
export interface UpdateOAuthClientData {
  name?: string;
  description?: string | null;
  redirectUris?: string[];
  allowedGrantTypes?: string[];
  allowedScopes?: string[];
  defaultScopes?: string[];
  clientType?: string;
  authMethod?: string;
  requirePkce?: boolean;
  requireUserConsent?: boolean;
  isFirstParty?: boolean;
  jwksUri?: string | null;
  jwks?: Record<string, any> | null;
  logoUri?: string | null;
  policyUri?: string | null;
  tosUri?: string | null;
  contacts?: string[];
  subjectType?: string;
  idTokenSignedResponseAlg?: string;
  idTokenEncryptedResponseAlg?: string | null;
  idTokenEncryptedResponseEnc?: string | null;
  userinfoSignedResponseAlg?: string | null;
  userinfoEncryptedResponseAlg?: string | null;
  userinfoEncryptedResponseEnc?: string | null;
  requestObjectSigningAlg?: string | null;
  requestObjectEncryptionAlg?: string | null;
  requestObjectEncryptionEnc?: string | null;
  tokenEndpointAuthSigningAlg?: string | null;
  defaultMaxAge?: number | null;
  requireAuthTime?: boolean;
  defaultAcrValues?: string[];
  initiateLoginUri?: string | null;
  softwareId?: string | null;
  softwareVersion?: string | null;
  metadata?: Record<string, any> | null;
}

/**
 * OAuth client filter options interface
 * Represents the options for filtering OAuth clients
 */
export interface OAuthClientFilterOptions {
  id?: string;
  userId?: string;
  clientId?: string;
  name?: string;
  clientType?: string;
  isFirstParty?: boolean;
  createdAtBefore?: Date;
  createdAtAfter?: Date;
  updatedAtBefore?: Date;
  updatedAtAfter?: Date;
}
