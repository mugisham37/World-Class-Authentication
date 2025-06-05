import { Injectable } from '@tsed/di';
import { logger } from '../../../infrastructure/logging/logger';
import type { CryptoService } from '../../../infrastructure/security/crypto/crypto.service';
import type { JwtService } from '../../../infrastructure/security/jwt/jwt.service';
import { BadRequestError, UnauthorizedError } from '../../../utils/error-handling';
import type { UserService } from '../../user/user.service';
import { ClientType } from '../models/client.model';
import { TokenType } from '../models/token.model';
import { oauthConfig } from '../oauth.config';
import type { ClientService } from './client.service';
import type { ConsentService } from './consent.service';
import type { TokenService } from './token.service';

@Injectable()
export class OAuthService {
  constructor(
    private clientService: ClientService,
    private tokenService: TokenService,
    private consentService: ConsentService,

    private userService: UserService,
    private cryptoService: CryptoService,
    private jwtService: JwtService
  ) {}

  /**
   * Handle authorization code grant
   * @param clientId Client ID
   * @param redirectUri Redirect URI
   * @param scopes Requested scopes
   * @param state State parameter
   * @param responseType Response type
   * @param nonce Nonce parameter (for OpenID Connect)
   * @param codeChallenge Code challenge (for PKCE)
   * @param codeChallengeMethod Code challenge method (for PKCE)
   * @param prompt Prompt parameter
   * @param maxAge Max age parameter
   * @param userId User ID (if already authenticated)
   * @returns Authorization request data
   */
  async handleAuthorizationRequest(
    clientId: string,
    redirectUri: string,
    scopes: string[],
    state: string,
    responseType: string,
    nonce?: string | undefined,
    codeChallenge?: string | undefined,
    codeChallengeMethod?: 'plain' | 'S256' | undefined,
    prompt?: string | undefined,
    maxAge?: number | undefined,
    userId?: string | undefined
  ): Promise<{
    client: any;
    redirectUri: string;
    scopes: string[];
    state: string;
    responseType: string;
    nonce?: string | undefined;
    codeChallenge?: string | undefined;
    codeChallengeMethod?: 'plain' | 'S256' | undefined;
    prompt?: string | undefined;
    maxAge?: number | undefined;
    userId?: string | undefined;
    requiresConsent: boolean;
    missingScopes?: string[] | undefined;
  }> {
    try {
      // Validate client
      const client = await this.clientService.findById(clientId);
      if (!client) {
        throw new BadRequestError('Invalid client', 'invalid_client');
      }

      // Validate redirect URI
      if (!this.validateRedirectUri(client.redirectUris, redirectUri)) {
        throw new BadRequestError('Invalid redirect URI', 'invalid_request');
      }

      // Validate response type
      if (!client.allowedResponseTypes.includes(responseType)) {
        throw new BadRequestError(
          `Response type '${responseType}' not allowed for this client`,
          'unsupported_response_type'
        );
      }

      // Validate scopes
      const validScopes = await this.validateScopes(scopes, client.allowedScopes);
      if (validScopes.length === 0) {
        throw new BadRequestError('No valid scopes requested', 'invalid_scope');
      }

      // Check if PKCE is required
      if (
        client.requirePkce ||
        (oauthConfig.features.pkce.forcePkceForPublicClients &&
          client.clientType === ClientType.PUBLIC)
      ) {
        if (!codeChallenge) {
          throw new BadRequestError('Code challenge is required', 'invalid_request');
        }
        if (!codeChallengeMethod) {
          codeChallengeMethod = 'plain'; // Default to plain if not specified
        }
      }

      // Check if user consent is required
      let requiresConsent = client.requireUserConsent && oauthConfig.consent.enabled;
      let missingScopes: string[] = [];

      if (userId && requiresConsent) {
        // Check if user has already consented to these scopes
        const existingConsent = await this.consentService.findByUserAndClient(userId, clientId);
        if (existingConsent) {
          // Check if all requested scopes are already consented
          missingScopes = validScopes.filter(scope => !existingConsent.scopes.includes(scope));
          if (missingScopes.length === 0) {
            requiresConsent = false;
          }
        }

        // Skip consent for first-party clients if configured
        if (client.isFirstParty && oauthConfig.consent.implicitForFirstParty) {
          requiresConsent = false;
        }
      }

      return {
        client,
        redirectUri,
        scopes: validScopes,
        state,
        responseType,
        nonce,
        codeChallenge,
        codeChallengeMethod,
        prompt,
        maxAge,
        userId,
        requiresConsent,
        missingScopes: missingScopes.length > 0 ? missingScopes : undefined,
      };
    } catch (error) {
      logger.error('Error handling authorization request', { error, clientId, redirectUri });
      throw error;
    }
  }

  /**
   * Create authorization code
   * @param clientId Client ID
   * @param userId User ID
   * @param redirectUri Redirect URI
   * @param scopes Authorized scopes
   * @param codeChallenge Code challenge (for PKCE)
   * @param codeChallengeMethod Code challenge method (for PKCE)
   * @param nonce Nonce parameter (for OpenID Connect)
   * @returns Authorization code
   */
  async createAuthorizationCode(
    clientId: string,
    userId: string,
    redirectUri: string,
    scopes: string[],
    codeChallenge?: string,
    codeChallengeMethod?: 'plain' | 'S256',
    nonce?: string
  ): Promise<string> {
    try {
      // Generate authorization code
      const code = this.cryptoService.generateRandomString(
        oauthConfig.tokens.authorizationCode.length
      );

      // Calculate expiration time
      const expiresAt = new Date(
        Date.now() + oauthConfig.tokens.authorizationCode.expiresIn * 1000
      );

      // Create token record
      await this.tokenService.create({
        clientId,
        userId,
        type: TokenType.AUTHORIZATION_CODE,
        value: code,
        scopes,
        expiresAt,
        redirectUri,
        codeChallenge,
        codeChallengeMethod,
        nonce,
        authTime: new Date(),
        audience: [oauthConfig.server.issuer], // Add required audience
      });

      return code;
    } catch (error) {
      logger.error('Error creating authorization code', { error, clientId, userId });
      throw error;
    }
  }

  /**
   * Exchange authorization code for tokens
   * @param code Authorization code
   * @param clientId Client ID
   * @param clientSecret Client secret (for confidential clients)
   * @param redirectUri Redirect URI
   * @param codeVerifier Code verifier (for PKCE)
   * @returns Access token, refresh token (optional), and ID token (optional)
   */
  async exchangeAuthorizationCode(
    code: string,
    clientId: string,
    clientSecret: string | null,
    redirectUri: string,
    codeVerifier?: string
  ): Promise<{
    accessToken: string;
    tokenType: string;
    expiresIn: number;
    refreshToken?: string | undefined;
    idToken?: string | undefined;
    scope: string;
  }> {
    try {
      // Validate client
      const client = await this.validateClient(clientId, clientSecret);

      // Find authorization code
      const authCode = await this.tokenService.findByValue(code, TokenType.AUTHORIZATION_CODE);
      if (!authCode) {
        throw new BadRequestError('Invalid authorization code', 'invalid_grant');
      }

      // Check if code is expired
      if (authCode.expiresAt < new Date() || authCode.revokedAt) {
        throw new BadRequestError('Authorization code expired or revoked', 'invalid_grant');
      }

      // Validate client ID
      if (authCode.clientId !== clientId) {
        throw new BadRequestError(
          'Authorization code was not issued to this client',
          'invalid_grant'
        );
      }

      // Validate redirect URI
      if (authCode.redirectUri !== redirectUri) {
        throw new BadRequestError('Redirect URI mismatch', 'invalid_grant');
      }

      // Validate PKCE if required
      if (authCode.codeChallenge) {
        if (!codeVerifier) {
          throw new BadRequestError('Code verifier is required', 'invalid_grant');
        }

        const method = authCode.codeChallengeMethod || 'plain';
        const calculatedChallenge =
          method === 'S256' ? this.cryptoService.generateCodeChallenge(codeVerifier) : codeVerifier;

        if (calculatedChallenge !== authCode.codeChallenge) {
          throw new BadRequestError('Code verifier is invalid', 'invalid_grant');
        }
      }

      // Revoke the authorization code (one-time use)
      await this.tokenService.revoke(authCode.id);

      // Generate access token
      const accessToken = await this.createAccessToken(
        client.id,
        authCode.userId,
        authCode.scopes,
        authCode.nonce
      );

      // Generate refresh token if offline_access scope is requested
      let refreshToken: string | undefined;
      if (authCode.scopes.includes('offline_access')) {
        refreshToken = await this.createRefreshToken(client.id, authCode.userId, authCode.scopes);
      }

      // Generate ID token if OpenID Connect is enabled and openid scope is requested
      let idToken: string | undefined;
      if (oauthConfig.oidc.enabled && authCode.scopes.includes('openid') && authCode.userId) {
        idToken = await this.createIdToken(
          client.id,
          authCode.userId,
          authCode.nonce,
          authCode.authTime,
          accessToken
        );
      }

      return {
        accessToken,
        tokenType: 'Bearer',
        expiresIn: oauthConfig.tokens.accessToken.expiresIn,
        refreshToken,
        idToken,
        scope: authCode.scopes.join(' '),
      };
    } catch (error) {
      logger.error('Error exchanging authorization code', { error, code, clientId });
      throw error;
    }
  }

  /**
   * Refresh access token
   * @param refreshToken Refresh token
   * @param clientId Client ID
   * @param clientSecret Client secret (for confidential clients)
   * @param scopes Requested scopes (must be a subset of original scopes)
   * @returns New access token and optionally a new refresh token
   */
  async refreshAccessToken(
    refreshToken: string,
    clientId: string,
    clientSecret: string | null,
    scopes?: string[]
  ): Promise<{
    accessToken: string;
    tokenType: string;
    expiresIn: number;
    refreshToken?: string | undefined;
    idToken?: string | undefined;
    scope: string;
  }> {
    try {
      // Validate client
      const client = await this.validateClient(clientId, clientSecret);

      // Find refresh token
      const token = await this.tokenService.findByValue(refreshToken, TokenType.REFRESH_TOKEN);
      if (!token) {
        throw new BadRequestError('Invalid refresh token', 'invalid_grant');
      }

      // Check if token is expired or revoked
      if (token.expiresAt < new Date() || token.revokedAt) {
        throw new BadRequestError('Refresh token expired or revoked', 'invalid_grant');
      }

      // Validate client ID
      if (token.clientId !== clientId) {
        throw new BadRequestError('Refresh token was not issued to this client', 'invalid_grant');
      }

      // Validate scopes (if provided)
      let validScopes = token.scopes;
      if (scopes && scopes.length > 0) {
        // Ensure requested scopes are a subset of the original scopes
        validScopes = scopes.filter(scope => token.scopes.includes(scope));
        if (validScopes.length === 0) {
          throw new BadRequestError('Invalid scopes requested', 'invalid_scope');
        }
      }

      // Generate new access token
      const accessToken = await this.createAccessToken(client.id, token.userId, validScopes);

      // Generate new refresh token if rotation is enabled
      let newRefreshToken: string | undefined;
      if (oauthConfig.features.refreshTokenRotation) {
        // Revoke the old refresh token
        await this.tokenService.revoke(token.id);

        // Create new refresh token
        newRefreshToken = await this.createRefreshToken(
          client.id,
          token.userId,
          validScopes,
          refreshToken // Link to previous token
        );
      }

      // Generate ID token if OpenID Connect is enabled and openid scope is requested
      let idToken: string | undefined;
      if (oauthConfig.oidc.enabled && validScopes.includes('openid') && token.userId) {
        idToken = await this.createIdToken(
          client.id,
          token.userId,
          undefined, // No nonce for refresh
          undefined, // No auth time for refresh
          accessToken
        );
      }

      return {
        accessToken,
        tokenType: 'Bearer',
        expiresIn: oauthConfig.tokens.accessToken.expiresIn,
        refreshToken: newRefreshToken,
        idToken,
        scope: validScopes.join(' '),
      };
    } catch (error) {
      logger.error('Error refreshing access token', { error, clientId });
      throw error;
    }
  }

  /**
   * Handle client credentials grant
   * @param clientId Client ID
   * @param clientSecret Client secret
   * @param scopes Requested scopes
   * @returns Access token
   */
  async handleClientCredentialsGrant(
    clientId: string,
    clientSecret: string,
    scopes: string[]
  ): Promise<{
    accessToken: string;
    tokenType: string;
    expiresIn: number;
    scope: string;
  }> {
    try {
      // Validate client
      const client = await this.validateClient(clientId, clientSecret);

      // Ensure client is confidential
      if (client.clientType !== ClientType.CONFIDENTIAL) {
        throw new BadRequestError(
          'Client credentials grant is only supported for confidential clients',
          'unauthorized_client'
        );
      }

      // Validate scopes
      const validScopes = await this.validateScopes(scopes, client.allowedScopes);
      if (validScopes.length === 0) {
        throw new BadRequestError('No valid scopes requested', 'invalid_scope');
      }

      // Generate access token
      const accessToken = await this.createAccessToken(
        client.id,
        undefined, // No user for client credentials
        validScopes
      );

      return {
        accessToken,
        tokenType: 'Bearer',
        expiresIn: oauthConfig.tokens.accessToken.expiresIn,
        scope: validScopes.join(' '),
      };
    } catch (error) {
      logger.error('Error handling client credentials grant', { error, clientId });
      throw error;
    }
  }

  /**
   * Create access token
   * @param clientId Client ID
   * @param userId User ID (optional)
   * @param scopes Authorized scopes
   * @param nonce Nonce parameter (for OpenID Connect)
   * @returns Access token
   */
  private async createAccessToken(
    clientId: string,
    userId?: string,
    scopes: string[] = [],
    nonce?: string
  ): Promise<string> {
    try {
      let accessToken: string;

      // Calculate expiration time
      const expiresAt = new Date(Date.now() + oauthConfig.tokens.accessToken.expiresIn * 1000);

      if (oauthConfig.features.jwtAccessTokens) {
        // Create JWT access token
        const payload: Record<string, any> = {
          sub: userId || clientId,
          client_id: clientId,
          exp: Math.floor(expiresAt.getTime() / 1000),
          iat: Math.floor(Date.now() / 1000),
          scope: scopes.join(' '),
          iss: oauthConfig.server.issuer,
          jti: this.cryptoService.generateUuid(),
        };

        // Add audience
        payload['aud'] = [oauthConfig.server.issuer];

        // Add nonce if provided
        if (nonce) {
          payload['nonce'] = nonce;
        }

        // Sign JWT
        accessToken = await this.jwtService.sign(payload, oauthConfig.tokens.accessToken.algorithm);
      } else {
        // Create opaque access token
        accessToken = this.cryptoService.generateRandomString(32);
      }

      // Create token record
      await this.tokenService.create({
        clientId,
        userId,
        type: TokenType.ACCESS_TOKEN,
        value: accessToken,
        scopes,
        expiresAt,
        nonce,
        audience: [oauthConfig.server.issuer], // Add required audience
      });

      return accessToken;
    } catch (error) {
      logger.error('Error creating access token', { error, clientId, userId });
      throw error;
    }
  }

  /**
   * Create refresh token
   * @param clientId Client ID
   * @param userId User ID
   * @param scopes Authorized scopes
   * @param previousToken Previous refresh token (for rotation)
   * @returns Refresh token
   */
  private async createRefreshToken(
    clientId: string,
    userId?: string,
    scopes: string[] = [],
    previousToken?: string
  ): Promise<string> {
    try {
      // Generate refresh token
      const refreshToken = this.cryptoService.generateRandomString(
        oauthConfig.tokens.refreshToken.length
      );

      // Calculate expiration time
      const expiresAt = new Date(Date.now() + oauthConfig.tokens.refreshToken.expiresIn * 1000);

      // Create token record
      await this.tokenService.create({
        clientId,
        userId,
        type: TokenType.REFRESH_TOKEN,
        value: refreshToken,
        scopes,
        expiresAt,
        previousToken,
        audience: [oauthConfig.server.issuer], // Add required audience
      });

      return refreshToken;
    } catch (error) {
      logger.error('Error creating refresh token', { error, clientId, userId });
      throw error;
    }
  }

  /**
   * Create ID token (OpenID Connect)
   * @param clientId Client ID
   * @param userId User ID
   * @param nonce Nonce parameter
   * @param authTime Authentication time
   * @param accessToken Access token (for at_hash claim)
   * @returns ID token
   */
  private async createIdToken(
    clientId: string,
    userId: string,
    nonce?: string,
    authTime?: Date,
    accessToken?: string
  ): Promise<string> {
    try {
      // Get client
      const client = await this.clientService.findById(clientId);
      if (!client) {
        throw new BadRequestError('Invalid client', 'invalid_client');
      }

      // Get user
      const user = await this.userService.findById(userId);
      if (!user) {
        throw new BadRequestError('Invalid user', 'invalid_request');
      }

      // Calculate expiration time
      const expiresAt = new Date(Date.now() + oauthConfig.tokens.idToken.expiresIn * 1000);

      // Create ID token payload
      const payload: Record<string, any> = {
        iss: oauthConfig.server.issuer,
        sub: userId,
        aud: clientId,
        exp: Math.floor(expiresAt.getTime() / 1000),
        iat: Math.floor(Date.now() / 1000),
      };

      // Add nonce if provided
      if (nonce) {
        payload['nonce'] = nonce;
      }

      // Add auth_time if available
      if (authTime) {
        payload['auth_time'] = Math.floor(authTime.getTime() / 1000);
      }

      // Add at_hash if access token is provided
      if (accessToken) {
        payload['at_hash'] = this.cryptoService.generateTokenHash(
          accessToken,
          oauthConfig.tokens.idToken.algorithm
        );
      }

      // Add user claims based on scopes
      // This would be expanded in a real implementation
      if (user.email) {
        payload['email'] = user.email;
        payload['email_verified'] = user.emailVerified || false;
      }

      // Sign ID token
      const idToken = await this.jwtService.sign(payload, oauthConfig.tokens.idToken.algorithm);

      // Create token record
      await this.tokenService.create({
        clientId,
        userId,
        type: TokenType.ID_TOKEN,
        value: idToken,
        scopes: ['openid'],
        expiresAt,
        nonce,
        audience: [clientId], // Add required audience (for ID tokens, audience is the client ID)
      });

      return idToken;
    } catch (error) {
      logger.error('Error creating ID token', { error, clientId, userId });
      throw error;
    }
  }

  /**
   * Validate client credentials
   * @param clientId Client ID
   * @param clientSecret Client secret (optional)
   * @returns Client if valid
   */
  private async validateClient(clientId: string, clientSecret: string | null): Promise<any> {
    try {
      // Find client
      const client = await this.clientService.findById(clientId);
      if (!client) {
        throw new UnauthorizedError('Invalid client', 'invalid_client');
      }

      // Validate client secret for confidential clients
      if (client.clientType === ClientType.CONFIDENTIAL) {
        if (!clientSecret) {
          throw new UnauthorizedError('Client authentication required', 'invalid_client');
        }

        const isValid = await this.clientService.validateClientSecret(clientId, clientSecret);
        if (!isValid) {
          throw new UnauthorizedError('Invalid client credentials', 'invalid_client');
        }
      }

      return client;
    } catch (error) {
      logger.error('Error validating client', { error, clientId });
      throw error;
    }
  }

  /**
   * Validate redirect URI
   * @param allowedUris Allowed redirect URIs
   * @param redirectUri Redirect URI to validate
   * @returns True if valid
   */
  private validateRedirectUri(allowedUris: string[], redirectUri: string): boolean {
    // Exact match
    if (allowedUris.includes(redirectUri)) {
      return true;
    }

    // Check for wildcard matches if allowed
    if (oauthConfig.clients.allowWildcardRedirectUris) {
      for (const uri of allowedUris) {
        if (uri.endsWith('*')) {
          const prefix = uri.slice(0, -1);
          if (redirectUri.startsWith(prefix)) {
            return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * Validate scopes
   * @param requestedScopes Requested scopes
   * @param allowedScopes Allowed scopes
   * @returns Valid scopes
   */
  private async validateScopes(
    requestedScopes: string[],
    allowedScopes: string[]
  ): Promise<string[]> {
    // If no scopes requested, use default scopes
    if (!requestedScopes || requestedScopes.length === 0) {
      return oauthConfig.clients.defaultScopes.filter(scope => allowedScopes.includes(scope));
    }

    // Filter out invalid scopes
    return requestedScopes.filter(scope => allowedScopes.includes(scope));
  }

  /**
   * Introspect token
   * @param token Token to introspect
   * @param tokenTypeHint Token type hint
   * @param clientId Client ID
   * @param clientSecret Client secret
   * @returns Token information
   */
  async introspectToken(
    token: string,
    tokenTypeHint?: string,
    clientId?: string,
    clientSecret?: string
  ): Promise<Record<string, any>> {
    try {
      // Validate client if provided
      if (clientId) {
        await this.validateClient(clientId, clientSecret || null);
      }

      // Try to find token based on type hint
      let tokenRecord: any = null;
      if (tokenTypeHint === 'access_token') {
        tokenRecord = await this.tokenService.findByValue(token, TokenType.ACCESS_TOKEN);
      } else if (tokenTypeHint === 'refresh_token') {
        tokenRecord = await this.tokenService.findByValue(token, TokenType.REFRESH_TOKEN);
      } else {
        // Try all token types
        tokenRecord =
          (await this.tokenService.findByValue(token, TokenType.ACCESS_TOKEN)) ||
          (await this.tokenService.findByValue(token, TokenType.REFRESH_TOKEN));
      }

      // If token not found or is expired/revoked, return inactive
      if (!tokenRecord || tokenRecord.expiresAt < new Date() || tokenRecord.revokedAt) {
        return { active: false };
      }

      // Build response
      const response: Record<string, any> = {
        active: true,
        client_id: tokenRecord.clientId,
        token_type: tokenRecord.type === TokenType.ACCESS_TOKEN ? 'access_token' : 'refresh_token',
        exp: Math.floor(tokenRecord.expiresAt.getTime() / 1000),
        iat: Math.floor(tokenRecord.issuedAt.getTime() / 1000),
        scope: tokenRecord.scopes.join(' '),
      };

      // Add user-specific claims
      if (tokenRecord.userId) {
        response['sub'] = tokenRecord.userId;
      }

      return response;
    } catch (error) {
      logger.error('Error introspecting token', { error });
      // Return inactive for any error
      return { active: false };
    }
  }

  /**
   * Revoke token
   * @param token Token to revoke
   * @param tokenTypeHint Token type hint
   * @param clientId Client ID
   * @param clientSecret Client secret
   * @returns Success status
   */
  async revokeToken(
    token: string,
    tokenTypeHint?: string,
    clientId?: string,
    clientSecret?: string
  ): Promise<boolean> {
    try {
      // Validate client if provided
      if (clientId) {
        await this.validateClient(clientId, clientSecret || null);
      }

      // Try to find token based on type hint
      let tokenRecord: any = null;
      if (tokenTypeHint === 'access_token') {
        tokenRecord = await this.tokenService.findByValue(token, TokenType.ACCESS_TOKEN);
      } else if (tokenTypeHint === 'refresh_token') {
        tokenRecord = await this.tokenService.findByValue(token, TokenType.REFRESH_TOKEN);
      } else {
        // Try all token types
        tokenRecord =
          (await this.tokenService.findByValue(token, TokenType.ACCESS_TOKEN)) ||
          (await this.tokenService.findByValue(token, TokenType.REFRESH_TOKEN));
      }

      // If token found, revoke it
      if (tokenRecord) {
        await this.tokenService.revoke(tokenRecord.id);
        return true;
      }

      // Token not found, but don't error
      return false;
    } catch (error) {
      logger.error('Error revoking token', { error });
      return false;
    }
  }

  /**
   * Get OpenID Connect discovery document
   * @returns Discovery document
   */
  getOpenIdConfiguration(): Record<string, any> {
    const baseUrl = oauthConfig.server.issuer;

    return {
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}${oauthConfig.server.authorizationEndpoint}`,
      token_endpoint: `${baseUrl}${oauthConfig.server.tokenEndpoint}`,
      userinfo_endpoint: `${baseUrl}${oauthConfig.server.userinfoEndpoint}`,
      jwks_uri: `${baseUrl}${oauthConfig.server.jwksEndpoint}`,
      registration_endpoint: oauthConfig.server.registrationEndpoint
        ? `${baseUrl}${oauthConfig.server.registrationEndpoint}`
        : undefined,
      scopes_supported: oauthConfig.clients.allowedScopes,
      response_types_supported: oauthConfig.clients.allowedResponseTypes,
      grant_types_supported: oauthConfig.clients.allowedGrantTypes,
      subject_types_supported: oauthConfig.oidc.subjectTypes,
      id_token_signing_alg_values_supported: oauthConfig.oidc.idTokenSigningAlgs,
      claims_supported: oauthConfig.oidc.supportedClaims,
      token_endpoint_auth_methods_supported: [
        'client_secret_basic',
        'client_secret_post',
        'client_secret_jwt',
        'private_key_jwt',
        'none',
      ],
      revocation_endpoint: `${baseUrl}${oauthConfig.server.revocationEndpoint}`,
      introspection_endpoint: `${baseUrl}${oauthConfig.server.introspectionEndpoint}`,
      end_session_endpoint: `${baseUrl}${oauthConfig.server.endSessionEndpoint}`,
      code_challenge_methods_supported: ['plain', 'S256'],
    };
  }

  /**
   * Get JWKS (JSON Web Key Set)
   * @returns JWKS
   */
  async getJwks(): Promise<Record<string, any>> {
    try {
      // In a real implementation, this would return the public keys used to verify tokens
      // For now, we'll return a placeholder
      return {
        keys: [
          {
            kty: 'RSA',
            use: 'sig',
            kid: 'default',
            alg: 'RS256',
            // These would be real public key components in a production system
            n: 'placeholder',
            e: 'AQAB',
          },
        ],
      };
    } catch (error) {
      logger.error('Error getting JWKS', { error });
      throw error;
    }
  }
}
