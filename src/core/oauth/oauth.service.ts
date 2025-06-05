import { Injectable } from "@tsed/di"
import * as crypto from "crypto"
import * as jwt from "jsonwebtoken"
import { oauthConfig } from "./oauth.config"
import { logger } from "../../infrastructure/logging/logger"
import type { ClientRepository } from "../../data/repositories/oauth/client.repository"
import type { TokenRepository } from "../../data/repositories/oauth/token.repository"
import type { AuthorizationCodeRepository } from "../../data/repositories/oauth/authorization-code.repository"
import type { ConsentRepository } from "../../data/repositories/oauth/consent.repository"
import type { UserRepository } from "../../data/repositories/user.repository"
import type { ScopeRepository } from "../../data/repositories/oauth/scope.repository"
import type { EventEmitter } from "../../infrastructure/events/event-emitter"
import { OAuthEvent } from "./oauth-events"
import { BadRequestError, NotFoundError, UnauthorizedError } from "../../utils/error-handling"
import { UserWithProfile } from "../../data/models/user.model"

/**
 * OAuth 2.0 service
 * Implements OAuth 2.0 and OpenID Connect functionality
 */
@Injectable()
export class OAuthService {
  constructor(
    private clientRepository: ClientRepository,
    private tokenRepository: TokenRepository,
    private authorizationCodeRepository: AuthorizationCodeRepository,
    // TODO: Will be used for consent management in future implementation
    private consentRepository: ConsentRepository,
    private userRepository: UserRepository,
    // TODO: Will be used for scope validation and management in future implementation
    private scopeRepository: ScopeRepository,
    private eventEmitter: EventEmitter,
  ) {}

  /**
   * Validate client credentials
   * @param clientId Client ID
   * @param clientSecret Client secret (optional for public clients)
   * @returns Client object if valid
   */
  async validateClient(clientId: string, clientSecret?: string): Promise<any> {
    try {
      // Find client
      const client = await this.clientRepository.findById(clientId)
      if (!client) {
        throw new NotFoundError("Client not found")
      }

      // Check if client is active
      if (!client.isActive) {
        throw new UnauthorizedError("Client is inactive")
      }

      // For confidential clients, validate client secret
      if (client.clientType === "confidential") {
        if (!clientSecret) {
          throw new UnauthorizedError("Client secret is required for confidential clients")
        }

        const isValidSecret = await this.verifyClientSecret(client, clientSecret)
        if (!isValidSecret) {
          throw new UnauthorizedError("Invalid client secret")
        }
      }

      return client
    } catch (error) {
      logger.error("Error validating client", { error, clientId })
      throw error
    }
  }

  /**
   * Verify client secret
   * @param client Client object
   * @param clientSecret Client secret to verify
   * @returns True if secret is valid
   */
  private async verifyClientSecret(client: any, clientSecret: string): Promise<boolean> {
    try {
      // If client uses hashed secrets
      if (client.secretHash) {
        // Compare hashed secret
        const hash = crypto.createHmac("sha256", oauthConfig.clientSecretSalt).update(clientSecret).digest("hex")
        return hash === client.secretHash
      }

      // Plain text comparison (not recommended for production)
      return client.secret === clientSecret
    } catch (error) {
      logger.error("Error verifying client secret", { error, clientId: client.id })
      return false
    }
  }

  /**
   * Validate redirect URI
   * @param client Client object
   * @param redirectUri Redirect URI to validate
   * @throws BadRequestError if redirect URI is invalid
   */
  private async validateRedirectUri(client: any, redirectUri: string): Promise<void> {
    // Check if redirect URI is in client's allowed redirect URIs
    if (!client.redirectUris || !Array.isArray(client.redirectUris) || !client.redirectUris.includes(redirectUri)) {
      throw new BadRequestError(`Invalid redirect URI: ${redirectUri}`)
    }
  }

  /**
   * Validate scope
   * @param client Client object
   * @param scope Scope to validate
   * @returns Validated scope
   * @throws BadRequestError if scope is invalid
   */
  private async validateScope(client: any, scope: string): Promise<string> {
    if (!scope) {
      // Use default scopes if none provided
      return oauthConfig.clients.defaultScopes.join(" ")
    }

    const requestedScopes = scope.split(" ")
    const allowedScopes = client.allowedScopes || oauthConfig.clients.allowedScopes

    // Check if all requested scopes are allowed
    const invalidScopes = requestedScopes.filter(s => !allowedScopes.includes(s))
    if (invalidScopes.length > 0) {
      throw new BadRequestError(`Invalid scopes: ${invalidScopes.join(", ")}`)
    }

    return scope
  }

  /**
   * Verify PKCE challenge
   * @param verifier Code verifier
   * @param challenge Code challenge
   * @param method Code challenge method
   * @returns True if valid, false otherwise
   */
  private async verifyPkceChallenge(verifier: string, challenge: string, method: string): Promise<boolean> {
    if (method === "S256") {
      // SHA-256 hash
      const hash = crypto
        .createHash("sha256")
        .update(verifier)
        .digest("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "")
      return hash === challenge
    } else if (method === "plain") {
      // Plain text comparison
      return verifier === challenge
    }
    
    return false
  }

  /**
   * Generate authorization code
   * @param clientId Client ID
   * @param userId User ID
   * @param redirectUri Redirect URI
   * @param scope Requested scope
   * @param codeChallenge PKCE code challenge (optional)
   * @param codeChallengeMethod PKCE code challenge method (optional)
   * @returns Authorization code
   */
  async generateAuthorizationCode(
    clientId: string,
    userId: string,
    redirectUri: string,
    scope: string,
    codeChallenge?: string,
    codeChallengeMethod?: string,
  ): Promise<string> {
    try {
      // Validate client
      const client = await this.validateClient(clientId)

      // Validate redirect URI
      await this.validateRedirectUri(client, redirectUri)

      // Validate scope
      const validatedScope = await this.validateScope(client, scope)

      // Generate code
      const code = crypto.randomBytes(32).toString("hex")

      // Calculate expiration
      const expiresAt = new Date(Date.now() + oauthConfig.tokens.authorizationCode.expiresIn * 1000)

      // Store authorization code
      await this.authorizationCodeRepository.create({
        code,
        clientId,
        userId,
        redirectUri,
        scope: validatedScope,
        expiresAt,
        codeChallenge,
        codeChallengeMethod,
      })

      // Emit authorization code generated event
      this.eventEmitter.emit(OAuthEvent.AUTHORIZATION_CODE_GENERATED, {
        clientId,
        userId,
        scope: validatedScope,
        timestamp: new Date(),
      })

      return code
    } catch (error) {
      logger.error("Error generating authorization code", { error, clientId, userId })
      throw error
    }
  }

  /**
   * Exchange authorization code for tokens
   * @param code Authorization code
   * @param clientId Client ID
   * @param clientSecret Client secret (optional for public clients)
   * @param redirectUri Redirect URI
   * @param codeVerifier PKCE code verifier (optional)
   * @returns Access token and refresh token
   */
  async exchangeAuthorizationCode(
    code: string,
    clientId: string,
    clientSecret: string | undefined,
    redirectUri: string,
    codeVerifier?: string,
  ): Promise<any> {
    try {
      // Validate client
      const client = await this.validateClient(clientId, clientSecret)

      // Find authorization code
      const authCode = await this.authorizationCodeRepository.findByCode(code)
      if (!authCode) {
        throw new NotFoundError("Authorization code not found")
      }

      // Check if code is expired
      if (authCode.expiresAt < new Date()) {
        throw new BadRequestError("Authorization code has expired")
      }

      // Check if code has been used
      if (authCode.isUsed) {
        throw new BadRequestError("Authorization code has already been used")
      }

      // Check if client IDs match
      if (authCode.clientId !== clientId) {
        throw new BadRequestError("Client ID mismatch")
      }

      // Check if redirect URIs match
      if (authCode.redirectUri !== redirectUri) {
        throw new BadRequestError("Redirect URI mismatch")
      }

      // Verify PKCE code verifier if code challenge exists
      if (authCode.codeChallenge && !codeVerifier) {
        throw new BadRequestError("Code verifier is required")
      }

      if (authCode.codeChallenge && codeVerifier) {
        const isValidVerifier = await this.verifyPkceChallenge(
          codeVerifier,
          authCode.codeChallenge,
          authCode.codeChallengeMethod || "plain",
        )
        if (!isValidVerifier) {
          throw new BadRequestError("Invalid code verifier")
        }
      }

      // Mark code as used
      await this.authorizationCodeRepository.markAsUsed(code)

      // Generate tokens
      const tokens = await this.generateTokens(client, authCode.userId, authCode.scope)

      // Emit token generated event
      this.eventEmitter.emit(OAuthEvent.TOKEN_ISSUED, {
        clientId,
        userId: authCode.userId,
        grantType: "authorization_code",
        scope: authCode.scope,
        timestamp: new Date(),
      })

      return tokens
    } catch (error) {
      logger.error("Error exchanging authorization code", { error, code, clientId })
      throw error
    }
  }

  /**
   * Generate tokens using client credentials grant
   * @param clientId Client ID
   * @param clientSecret Client secret
   * @param scope Requested scope
   * @returns Access token
   */
  async clientCredentialsGrant(clientId: string, clientSecret: string, scope: string): Promise<any> {
    try {
      // Validate client
      const client = await this.validateClient(clientId, clientSecret)

      // Check if client is allowed to use client credentials grant
      if (!client.allowedGrantTypes.includes("client_credentials")) {
        throw new BadRequestError("Client is not allowed to use client credentials grant")
      }

      // Validate scope
      const validatedScope = await this.validateScope(client, scope)

      // Generate access token (no refresh token for client credentials)
      const accessToken = await this.generateAccessToken(client, null, validatedScope)

      // Emit token generated event
      this.eventEmitter.emit(OAuthEvent.TOKEN_ISSUED, {
        clientId,
        grantType: "client_credentials",
        scope: validatedScope,
        timestamp: new Date(),
      })

      return {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: oauthConfig.tokens.accessToken.expiresIn,
        scope: validatedScope,
      }
    } catch (error) {
      logger.error("Error in client credentials grant", { error, clientId })
      throw error
    }
  }

  /**
   * Refresh access token using refresh token
   * @param refreshToken Refresh token
   * @param clientId Client ID
   * @param clientSecret Client secret (optional for public clients)
   * @param scope Requested scope (optional)
   * @returns New access token and refresh token
   */
  async refreshToken(
    refreshToken: string,
    clientId: string,
    clientSecret: string | undefined,
    scope?: string,
  ): Promise<any> {
    try {
      // Validate client
      const client = await this.validateClient(clientId, clientSecret)

      // Find refresh token
      const token = await this.tokenRepository.findByValue(refreshToken, "refresh_token")
      if (!token) {
        throw new NotFoundError("Refresh token not found")
      }

      // Check if token is expired
      if (token.expiresAt < new Date()) {
        throw new BadRequestError("Refresh token has expired")
      }

      // Check if token has been revoked
      if (token.revokedAt) {
        throw new BadRequestError("Refresh token has been revoked")
      }

      // Check if client IDs match
      if (token.clientId !== clientId) {
        throw new BadRequestError("Client ID mismatch")
      }

      // Validate scope (if provided)
      let validatedScope = token.scopes.join(" ")
      if (scope) {
        // New scope must be equal to or a subset of the original scope
        const originalScopes = token.scopes
        const requestedScopes = scope.split(" ")
        const isSubset = requestedScopes.every((s) => originalScopes.includes(s))
        if (!isSubset) {
          throw new BadRequestError("Requested scope exceeds original scope")
        }
        validatedScope = scope
      }

      // Revoke old token if refresh token rotation is enabled
      if (oauthConfig.features.refreshTokenRotation) {
        await this.tokenRepository.revoke(token.id)
      }

      // Generate new tokens
      const tokens = await this.generateTokens(client, token.userId, validatedScope)

      // Emit token refreshed event
      this.eventEmitter.emit(OAuthEvent.TOKEN_REFRESHED, {
        clientId,
        userId: token.userId,
        scope: validatedScope,
        timestamp: new Date(),
      })

      return tokens
    } catch (error) {
      logger.error("Error refreshing token", { error, clientId })
      throw error
    }
  }

  /**
   * Revoke a token
   * @param token Token to revoke (access or refresh)
   * @param tokenTypeHint Token type hint (access_token or refresh_token)
   * @param clientId Client ID
   * @param clientSecret Client secret (optional for public clients)
   * @returns Success status
   */
  async revokeToken(
    token: string,
    tokenTypeHint: string | undefined,
    clientId: string,
    clientSecret: string | undefined,
  ): Promise<boolean> {
    try {
      // Validate client
      await this.validateClient(clientId, clientSecret)

      let tokenRecord

      // Try to find token based on hint
      if (tokenTypeHint === "refresh_token") {
        tokenRecord = await this.tokenRepository.findByValue(token, "refresh_token")
      } else if (tokenTypeHint === "access_token") {
        tokenRecord = await this.tokenRepository.findByValue(token, "access_token")
      }

      // If not found or no hint, try both
      if (!tokenRecord) {
        tokenRecord =
          (await this.tokenRepository.findByValue(token, "access_token")) ||
          (await this.tokenRepository.findByValue(token, "refresh_token"))
      }

      // If token not found, return success (as per RFC 7009)
      if (!tokenRecord) {
        return true
      }

      // Check if client IDs match
      if (tokenRecord.clientId !== clientId) {
        throw new BadRequestError("Client ID mismatch")
      }

      // Revoke token
      await this.tokenRepository.revoke(tokenRecord.id)

      // Emit token revoked event
      this.eventEmitter.emit(OAuthEvent.TOKEN_REVOKED, {
        clientId,
        userId: tokenRecord.userId,
        tokenId: tokenRecord.id,
        timestamp: new Date(),
      })

      return true
    } catch (error) {
      logger.error("Error revoking token", { error, clientId })
      throw error
    }
  }

  /**
   * Introspect a token
   * @param token Token to introspect
   * @param tokenTypeHint Token type hint (access_token or refresh_token)
   * @param clientId Client ID
   * @param clientSecret Client secret (optional for public clients)
   * @returns Token information
   */
  async introspectToken(
    token: string,
    tokenTypeHint: string | undefined,
    clientId: string,
    clientSecret: string | undefined,
  ): Promise<any> {
    try {
      // Validate client
      await this.validateClient(clientId, clientSecret)

      let tokenRecord

      // Try to find token based on hint
      if (tokenTypeHint === "refresh_token") {
        tokenRecord = await this.tokenRepository.findByValue(token, "refresh_token")
      } else if (tokenTypeHint === "access_token") {
        tokenRecord = await this.tokenRepository.findByValue(token, "access_token")
      }

      // If not found or no hint, try both
      if (!tokenRecord) {
        tokenRecord =
          (await this.tokenRepository.findByValue(token, "access_token")) ||
          (await this.tokenRepository.findByValue(token, "refresh_token"))
      }

      // If token not found, return inactive
      if (!tokenRecord) {
        return { active: false }
      }

      // Check if token is expired
      if (tokenRecord.expiresAt < new Date()) {
        return { active: false }
      }

      // Check if token is revoked
      if (tokenRecord.revokedAt) {
        return { active: false }
      }

      // Emit token introspected event
      this.eventEmitter.emit(OAuthEvent.TOKEN_INTROSPECTED, {
        clientId,
        userId: tokenRecord.userId,
        tokenId: tokenRecord.id,
        timestamp: new Date(),
      })

      // Return token information
      return {
        active: true,
        client_id: tokenRecord.clientId,
        user_id: tokenRecord.userId,
        scope: tokenRecord.scopes.join(" "),
        token_type: tokenRecord.type === "access_token" ? "access_token" : "refresh_token",
        exp: Math.floor(tokenRecord.expiresAt.getTime() / 1000),
        iat: Math.floor(tokenRecord.issuedAt.getTime() / 1000),
        sub: tokenRecord.userId,
        iss: oauthConfig.server.issuer,
      }
    } catch (error) {
      logger.error("Error introspecting token", { error, clientId })
      throw error
    }
  }

  /**
   * Get user information (OpenID Connect userinfo endpoint)
   * @param accessToken Access token
   * @returns User information
   */
  async getUserInfo(accessToken: string): Promise<any> {
    try {
      // Find token
      const token = await this.tokenRepository.findByValue(accessToken, "access_token")
      if (!token) {
        throw new NotFoundError("Access token not found")
      }

      // Check if token is expired
      if (token.expiresAt < new Date()) {
        throw new BadRequestError("Access token has expired")
      }

      // Check if token is revoked
      if (token.revokedAt) {
        throw new BadRequestError("Access token has been revoked")
      }

      // Check if token has openid scope
      const scopes = token.scopes
      if (!scopes.includes("openid")) {
        throw new BadRequestError("Access token does not have openid scope")
      }

      // Get user with profile
      const user = await this.userRepository.findById(token.userId) as UserWithProfile
      if (!user) {
        throw new NotFoundError("User not found")
      }

      // Build response based on scopes
      const response: Record<string, any> = {
        sub: user.id,
      }

      if (scopes.includes("profile")) {
        response["name"] = user.username
        response["preferred_username"] = user.username
        response["updated_at"] = Math.floor(user.updatedAt.getTime() / 1000)
      }

      if (scopes.includes("email")) {
        response["email"] = user.email
        response["email_verified"] = user.emailVerified
      }

      if (scopes.includes("phone") && user.profile) {
        response["phone_number"] = user.profile.phone
        response["phone_number_verified"] = false // Default to false if not available
      }

      return response
    } catch (error) {
      logger.error("Error getting user info", { error })
      throw error
    }
  }

  /**
   * Register a new client (dynamic client registration)
   * @param registrationRequest Client registration request
   * @param initialAccessToken Initial access token (optional)
   * @returns Registered client
   */
  async registerClient(registrationRequest: Record<string, any>, initialAccessToken?: string): Promise<any> {
    try {
      // Check if dynamic registration is enabled
      if (!oauthConfig.clients.dynamicRegistration) {
        throw new BadRequestError("Dynamic client registration is not enabled")
      }

      // Validate initial access token if required
      if (oauthConfig.clients.dynamicRegistration && initialAccessToken === undefined) {
        throw new UnauthorizedError("Initial access token is required")
      }

      // Validate registration request
      this.validateClientRegistrationRequest(registrationRequest)

      // Generate client ID and secret
      const clientId = crypto.randomBytes(16).toString("hex")
      const clientSecret = crypto.randomBytes(32).toString("hex")

      // Determine client type
      const clientType = registrationRequest["token_endpoint_auth_method"] === "none" ? "public" : "confidential"

      // Create client
      await this.clientRepository.create({
        id: clientId,
        userId: "system", // Default system user ID for dynamically registered clients
        clientId: clientId,
        clientSecret: clientSecret,
        secret: clientSecret,
        name: registrationRequest["client_name"],
        description: registrationRequest["client_description"] || "",
        clientType,
        redirectUris: registrationRequest["redirect_uris"],
        allowedGrantTypes: registrationRequest["grant_types"] || ["authorization_code"],
        allowedScopes: registrationRequest["scope"] ? registrationRequest["scope"].split(" ") : ["openid"],
        authMethod: registrationRequest["token_endpoint_auth_method"] || "client_secret_basic",
        allowedResponseTypes: registrationRequest["response_types"] || ["code"],
        logoUri: registrationRequest["logo_uri"],
        policyUri: registrationRequest["policy_uri"],
        tosUri: registrationRequest["tos_uri"],
        jwksUri: registrationRequest["jwks_uri"],
        jwks: registrationRequest["jwks"],
        subjectType: registrationRequest["subject_type"] || "public",
        idTokenSignedResponseAlg: registrationRequest["id_token_signed_response_alg"] || "RS256",
        idTokenEncryptedResponseAlg: registrationRequest["id_token_encrypted_response_alg"],
        idTokenEncryptedResponseEnc: registrationRequest["id_token_encrypted_response_enc"],
        userinfoSignedResponseAlg: registrationRequest["userinfo_signed_response_alg"],
        userinfoEncryptedResponseAlg: registrationRequest["userinfo_encrypted_response_alg"],
        userinfoEncryptedResponseEnc: registrationRequest["userinfo_encrypted_response_enc"],
        requestObjectSigningAlg: registrationRequest["request_object_signing_alg"],
        requestObjectEncryptionAlg: registrationRequest["request_object_encryption_alg"],
        requestObjectEncryptionEnc: registrationRequest["request_object_encryption_enc"],
        tokenEndpointAuthSigningAlg: registrationRequest["token_endpoint_auth_signing_alg"],
        defaultMaxAge: registrationRequest["default_max_age"],
        requireAuthTime: registrationRequest["require_auth_time"] || false,
        defaultAcrValues: registrationRequest["default_acr_values"],
        initiateLoginUri: registrationRequest["initiate_login_uri"],
        isActive: true,
      })

      // Emit client registered event
      this.eventEmitter.emit(OAuthEvent.CLIENT_CREATED, {
        clientId,
        clientName: registrationRequest["client_name"],
        timestamp: new Date(),
      })

      // Return client information
      return {
        client_id: clientId,
        client_secret: clientSecret,
        client_id_issued_at: Math.floor(Date.now() / 1000),
        client_secret_expires_at: 0, // Never expires
        registration_access_token: this.generateRegistrationAccessToken(clientId),
        registration_client_uri: `${oauthConfig.server.issuer}${oauthConfig.server.registrationEndpoint}/${clientId}`,
        ...registrationRequest,
      }
    } catch (error) {
      logger.error("Error registering client", { error })
      throw error
    }
  }

  /**
   * Validate client registration request
   * @param request Client registration request
   */
  private validateClientRegistrationRequest(request: Record<string, any>): void {
    // Check required fields
    if (!request["redirect_uris"] || !Array.isArray(request["redirect_uris"]) || request["redirect_uris"].length === 0) {
      throw new BadRequestError("redirect_uris is required and must be an array")
    }

    if (!request["client_name"]) {
      throw new BadRequestError("client_name is required")
    }

    // Validate redirect URIs
    for (const uri of request["redirect_uris"]) {
      try {
        const url = new URL(uri)
        if (!url.protocol.startsWith("http")) {
          throw new BadRequestError(`Invalid redirect URI: ${uri}. Must use HTTP or HTTPS protocol.`)
        }
      } catch (error) {
        throw new BadRequestError(`Invalid redirect URI: ${uri}`)
      }
    }

    // Validate grant types
    if (request["grant_types"]) {
      if (!Array.isArray(request["grant_types"])) {
        throw new BadRequestError("grant_types must be an array")
      }

      const allowedGrantTypes = oauthConfig.clients.allowedGrantTypes
      for (const grantType of request["grant_types"]) {
        if (!allowedGrantTypes.includes(grantType)) {
          throw new BadRequestError(`Unsupported grant type: ${grantType}`)
        }
      }
    }

    // Validate response types
    if (request["response_types"]) {
      if (!Array.isArray(request["response_types"])) {
        throw new BadRequestError("response_types must be an array")
      }

      const allowedResponseTypes = oauthConfig.clients.allowedResponseTypes
      for (const responseType of request["response_types"]) {
        if (!allowedResponseTypes.includes(responseType)) {
          throw new BadRequestError(`Unsupported response type: ${responseType}`)
        }
      }
    }

    // Validate application type
    if (request["application_type"] && !["web", "native"].includes(request["application_type"])) {
      throw new BadRequestError("application_type must be 'web' or 'native'")
    }

    // Validate token endpoint auth method
    if (
      request["token_endpoint_auth_method"] &&
      !["none", "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"].includes(
        request["token_endpoint_auth_method"],
      )
    ) {
      throw new BadRequestError("Unsupported token_endpoint_auth_method")
    }

    // Validate subject type
    if (request["subject_type"] && !["public", "pairwise"].includes(request["subject_type"])) {
      throw new BadRequestError("subject_type must be 'public' or 'pairwise'")
    }
  }

  /**
   * Generate registration access token for client management
   * @param clientId Client ID
   * @returns Registration access token
   */
  private generateRegistrationAccessToken(clientId: string): string {
    try {
      // In a real implementation, this would generate and store a token
      // For now, we'll use a simple JWT
      const secret = process.env["JWT_SECRET"] || "default-registration-secret"
      return jwt.sign(
        {
          client_id: clientId,
          type: "registration_access_token",
        },
        secret,
        {
          expiresIn: "1y",
          issuer: oauthConfig.server.issuer,
        },
      )
    } catch (error) {
      logger.error("Error generating registration access token", { error, clientId })
      throw error
    }
  }

  /**
   * Generate tokens (access token and refresh token)
   * @param client Client object
   * @param userId User ID (null for client credentials)
   * @param scope Scope
   * @returns Access token and refresh token
   */
  private async generateTokens(client: any, userId: string | null, scope: string): Promise<any> {
    try {
      // Generate access token
      const accessToken = await this.generateAccessToken(client, userId, scope)

      // Calculate access token expiration
      const accessTokenExpiresIn = oauthConfig.tokens.accessToken.expiresIn

      // Generate refresh token if applicable
      let refreshToken = null

      if (userId && scope.includes("offline_access") && client.allowedGrantTypes.includes("refresh_token")) {
        refreshToken = await this.generateRefreshToken(client, userId, scope)
      }

      // Generate ID token if openid scope is requested
      let idToken = null
      if (scope.includes("openid") && userId) {
        idToken = await this.generateIdToken(client, userId, scope)
      }

      // Build response
      const response: Record<string, any> = {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: accessTokenExpiresIn,
        scope,
      }

      if (refreshToken) {
        response["refresh_token"] = refreshToken
      }

      if (idToken) {
        response["id_token"] = idToken
      }

      return response
    } catch (error) {
      logger.error("Error generating tokens", { error, clientId: client.id, userId })
      throw error
    }
  }

  /**
   * Generate access token
   * @param client Client object
   * @param userId User ID (null for client credentials)
   * @param scope Requested scope
   * @returns Access token
   */
  private async generateAccessToken(client: any, userId: string | null, scope: string): Promise<string> {
    try {
      const expiresAt = new Date(Date.now() + oauthConfig.tokens.accessToken.expiresIn * 1000)
      
      if (oauthConfig.features.jwtAccessTokens) {
        const payload: Record<string, any> = {
          client_id: client.id,
          scope,
          iss: oauthConfig.server.issuer,
          aud: client.id,
          jti: crypto.randomBytes(16).toString('hex'),
          exp: Math.floor(expiresAt.getTime() / 1000),
          iat: Math.floor(Date.now() / 1000)
        }

        if (userId) {
          payload["sub"] = userId
        }

        // Ensure we have a valid secret for signing
        const secret = oauthConfig.tokens.accessToken.secret || "default-secret"
        return jwt.sign(payload, secret)
      }

      const accessToken = crypto.randomBytes(32).toString('hex')
      
      await this.tokenRepository.create({
        type: 'access_token',
        value: accessToken,
        clientId: client.id,
        userId,
        scopes: scope.split(' '),
        expiresAt,
        issuedAt: new Date()
      })

      return accessToken
    } catch (error) {
      logger.error('Error generating access token', { error })
      throw error
    }
  }

  /**
   * Generate refresh token
   * @param client Client object
   * @param userId User ID
   * @param scope Scope
   * @returns Refresh token
   */
  private async generateRefreshToken(client: any, userId: string, scope: string): Promise<string> {
    try {
      const expiresAt = new Date(Date.now() + oauthConfig.tokens.refreshToken.expiresIn * 1000)
      const refreshToken = crypto.randomBytes(32).toString("hex")

      await this.tokenRepository.create({
        type: "refresh_token",
        value: refreshToken,
        clientId: client.id,
        userId,
        scopes: scope.split(" "),
        expiresAt,
        issuedAt: new Date()
      });

      return refreshToken;
    } catch (error) {
      logger.error("Error generating refresh token", { error });
      throw error;
    }
  }

  /**
   * Generate ID token for OpenID Connect
   * @param client Client object
   * @param userId User ID
   * @param scope Requested scope
   * @returns ID token
   */
  private async generateIdToken(client: any, userId: string, scope: string): Promise<string> {
    try {
      const user = await this.userRepository.findById(userId) as UserWithProfile
      if (!user) {
        throw new NotFoundError('User not found')
      }

      const payload: Record<string, any> = {
        sub: userId,
        iss: oauthConfig.server.issuer,
        aud: client.id,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + oauthConfig.tokens.idToken.expiresIn
      }

      // Add claims based on scope
      if (scope.includes('profile')) {
        payload["name"] = user.username
        payload["preferred_username"] = user.username
        if (user.profile) {
          if (user.profile.firstName) payload["given_name"] = user.profile.firstName
          if (user.profile.lastName) payload["family_name"] = user.profile.lastName
        }
      }

      if (scope.includes('email')) {
        payload["email"] = user.email
        payload["email_verified"] = user.emailVerified
      }

      if (scope.includes('phone') && user.profile && user.profile.phone) {
        payload["phone_number"] = user.profile.phone
        payload["phone_number_verified"] = false // Default to false
      }

      // Ensure we have a valid secret for signing
      const secret = process.env["JWT_SECRET"] || "default-secret"
      return jwt.sign(payload, secret)
    } catch (error) {
      logger.error('Error generating ID token', { error })
      throw error
    }
  }
}
