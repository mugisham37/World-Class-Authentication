import { Injectable } from "@tsed/di"
import * as crypto from "crypto"
import { v4 as uuidv4 } from "uuid"
import { Client, ClientType, ClientAuthMethod, CreateClientInput, UpdateClientInput } from "../models/client.model"
import { logger } from "../../../infrastructure/logging/logger"
import { oauthConfig } from "../oauth.config"
import { EventEmitter } from "../../../infrastructure/events/event-emitter"
import { OAuthEvent } from "../oauth-events"
import { BadRequestError, NotFoundError } from "../../../utils/error-handling"

/**
 * Service for managing OAuth clients
 */
@Injectable()
export class ClientService {
  constructor(
    private eventEmitter: EventEmitter,
    // In a real implementation, this would be injected from a repository
    // private clientRepository: ClientRepository
  ) {
    // Initialize with some default clients for development
    this.initializeDefaultClients()
  }

  // In-memory client storage for demonstration
  private clients: Map<string, Client> = new Map()

  /**
   * Initialize default clients for development
   */
  private initializeDefaultClients(): void {
    // First-party client (e.g., your own web application)
    const webAppClient: Client = {
      id: "web-app-client",
      name: "Web Application",
      description: "First-party web application client",
      secret: "web-app-secret",
      secretHash: crypto.createHmac("sha256", "salt").update("web-app-secret").digest("hex"),
      clientType: ClientType.CONFIDENTIAL,
      authMethod: ClientAuthMethod.CLIENT_SECRET_BASIC,
      redirectUris: ["https://app.example.com/callback"],
      postLogoutRedirectUris: ["https://app.example.com"],
      allowedGrantTypes: ["authorization_code", "refresh_token"],
      allowedResponseTypes: ["code"],
      allowedScopes: ["openid", "profile", "email", "offline_access"],
      defaultScopes: ["openid", "profile"],
      requirePkce: false,
      requireSignedRequestObject: false,
      requireUserConsent: false,
      isFirstParty: true,
      subjectType: "public",
      idTokenSignedResponseAlg: "RS256",
      requireAuthTime: false,
      defaultAcrValues: [],
      contacts: [],
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
    }

    // Third-party client (e.g., a partner application)
    const partnerClient: Client = {
      id: "partner-client",
      name: "Partner Application",
      description: "Third-party partner application",
      secret: "partner-secret",
      secretHash: crypto.createHmac("sha256", "salt").update("partner-secret").digest("hex"),
      clientType: ClientType.CONFIDENTIAL,
      authMethod: ClientAuthMethod.CLIENT_SECRET_BASIC,
      redirectUris: ["https://partner.example.com/callback"],
      postLogoutRedirectUris: ["https://partner.example.com"],
      allowedGrantTypes: ["authorization_code", "refresh_token"],
      allowedResponseTypes: ["code"],
      allowedScopes: ["openid", "profile", "email"],
      defaultScopes: ["openid", "profile"],
      requirePkce: true,
      requireSignedRequestObject: false,
      requireUserConsent: true,
      isFirstParty: false,
      subjectType: "public",
      idTokenSignedResponseAlg: "RS256",
      requireAuthTime: true,
      defaultAcrValues: [],
      contacts: [],
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
    }

    // Mobile application client
    const mobileClient: Client = {
      id: "mobile-client",
      name: "Mobile Application",
      description: "Mobile application client",
      clientType: ClientType.PUBLIC,
      authMethod: ClientAuthMethod.NONE,
      redirectUris: ["com.example.app:/callback"],
      postLogoutRedirectUris: ["com.example.app:/"],
      allowedGrantTypes: ["authorization_code", "refresh_token"],
      allowedResponseTypes: ["code"],
      allowedScopes: ["openid", "profile", "email", "offline_access"],
      defaultScopes: ["openid", "profile"],
      requirePkce: true,
      requireSignedRequestObject: false,
      requireUserConsent: true,
      isFirstParty: true,
      subjectType: "public",
      idTokenSignedResponseAlg: "RS256",
      requireAuthTime: false,
      defaultAcrValues: [],
      contacts: [],
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
    }

    // Service client (for machine-to-machine communication)
    const serviceClient: Client = {
      id: "service-client",
      name: "Service Client",
      description: "Service client for machine-to-machine communication",
      secret: "service-secret",
      secretHash: crypto.createHmac("sha256", "salt").update("service-secret").digest("hex"),
      clientType: ClientType.CONFIDENTIAL,
      authMethod: ClientAuthMethod.CLIENT_SECRET_BASIC,
      redirectUris: [],
      postLogoutRedirectUris: [],
      allowedGrantTypes: ["client_credentials"],
      allowedResponseTypes: [],
      allowedScopes: ["api:read", "api:write"],
      defaultScopes: ["api:read"],
      requirePkce: false,
      requireSignedRequestObject: false,
      requireUserConsent: false,
      isFirstParty: true,
      subjectType: "public",
      idTokenSignedResponseAlg: "RS256",
      requireAuthTime: false,
      defaultAcrValues: [],
      contacts: [],
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
    }

    // Add clients to the map
    this.clients.set(webAppClient.id, webAppClient)
    this.clients.set(partnerClient.id, partnerClient)
    this.clients.set(mobileClient.id, mobileClient)
    this.clients.set(serviceClient.id, serviceClient)
  }

  /**
   * Find client by ID
   * @param id Client ID
   * @returns Client or null if not found
   */
  async findById(id: string): Promise<Client | null> {
    try {
      // In a real implementation, this would query the database
      const client = this.clients.get(id)
      return client || null
    } catch (error) {
      logger.error("Error finding client by ID", { error, id })
      return null
    }
  }

  /**
   * Find all clients
   * @returns Array of clients
   */
  async findAll(): Promise<Client[]> {
    try {
      // In a real implementation, this would query the database
      return Array.from(this.clients.values())
    } catch (error) {
      logger.error("Error finding all clients", { error })
      return []
    }
  }

  /**
   * Create a new client
   * @param data Client data
   * @returns Created client
   */
  async create(data: CreateClientInput): Promise<Client> {
    try {
      // Generate client ID
      const id = uuidv4()

      // Hash client secret if provided
      let secretHash: string | undefined
      if (data.secret) {
        secretHash = crypto.createHmac("sha256", oauthConfig.clientSecretSalt || "salt").update(data.secret).digest("hex")
      }

      // Create client
      const client: Client = {
        ...data,
        id,
        secretHash,
        createdAt: new Date(),
        updatedAt: new Date(),
        isActive: true,
      }

      // In a real implementation, this would save to the database
      this.clients.set(id, client)

      // Emit client created event
      this.eventEmitter.emit(OAuthEvent.CLIENT_CREATED, {
        clientId: id,
        clientName: data.name,
        timestamp: new Date(),
      })

      return client
    } catch (error) {
      logger.error("Error creating client", { error })
      throw error
    }
  }

  /**
   * Update a client
   * @param id Client ID
   * @param data Client data to update
   * @returns Updated client
   */
  async update(id: string, data: UpdateClientInput): Promise<Client> {
    try {
      // Find client
      const client = await this.findById(id)
      if (!client) {
        throw new NotFoundError("Client not found")
      }

      // Hash client secret if provided
      let secretHash = client.secretHash
      if (data.secret) {
        secretHash = crypto.createHmac("sha256", oauthConfig.clientSecretSalt || "salt").update(data.secret).digest("hex")
      }

      // Update client - preserve required properties from the original client
      // and only override with provided data
      const updatedClient: Client = {
        ...client,
        // Only apply updates for properties that are provided
        name: data.name ?? client.name,
        description: data.description ?? client.description,
        clientType: data.clientType ?? client.clientType,
        authMethod: data.authMethod ?? client.authMethod,
        redirectUris: data.redirectUris ?? client.redirectUris,
        postLogoutRedirectUris: data.postLogoutRedirectUris ?? client.postLogoutRedirectUris,
        allowedGrantTypes: data.allowedGrantTypes ?? client.allowedGrantTypes,
        allowedResponseTypes: data.allowedResponseTypes ?? client.allowedResponseTypes,
        allowedScopes: data.allowedScopes ?? client.allowedScopes,
        defaultScopes: data.defaultScopes ?? client.defaultScopes,
        requirePkce: data.requirePkce ?? client.requirePkce,
        requireSignedRequestObject: data.requireSignedRequestObject ?? client.requireSignedRequestObject,
        requireUserConsent: data.requireUserConsent ?? client.requireUserConsent,
        isFirstParty: data.isFirstParty ?? client.isFirstParty,
        subjectType: data.subjectType ?? client.subjectType,
        idTokenSignedResponseAlg: data.idTokenSignedResponseAlg ?? client.idTokenSignedResponseAlg,
        requireAuthTime: data.requireAuthTime ?? client.requireAuthTime,
        defaultAcrValues: data.defaultAcrValues ?? client.defaultAcrValues,
        isActive: data.isActive ?? client.isActive,
        secretHash,
        updatedAt: new Date(),
      }

      // In a real implementation, this would update the database
      this.clients.set(id, updatedClient)

      // Emit client updated event
      this.eventEmitter.emit(OAuthEvent.CLIENT_UPDATED, {
        clientId: id,
        clientName: updatedClient.name,
        timestamp: new Date(),
      })

      return updatedClient
    } catch (error) {
      logger.error("Error updating client", { error, id })
      throw error
    }
  }

  /**
   * Delete a client
   * @param id Client ID
   * @returns True if deleted
   */
  async delete(id: string): Promise<boolean> {
    try {
      // Find client
      const client = await this.findById(id)
      if (!client) {
        throw new NotFoundError("Client not found")
      }

      // In a real implementation, this would delete from the database
      this.clients.delete(id)

      // Emit client deleted event
      this.eventEmitter.emit(OAuthEvent.CLIENT_DELETED, {
        clientId: id,
        clientName: client.name,
        timestamp: new Date(),
      })

      return true
    } catch (error) {
      logger.error("Error deleting client", { error, id })
      throw error
    }
  }

  /**
   * Regenerate client secret
   * @param id Client ID
   * @returns New client secret
   */
  async regenerateSecret(id: string): Promise<string> {
    try {
      // Find client
      const client = await this.findById(id)
      if (!client) {
        throw new NotFoundError("Client not found")
      }

      // Check if client is confidential
      if (client.clientType !== ClientType.CONFIDENTIAL) {
        throw new BadRequestError("Cannot regenerate secret for public client")
      }

      // Generate new secret
      const secret = crypto.randomBytes(32).toString("hex")
      const secretHash = crypto.createHmac("sha256", oauthConfig.clientSecretSalt || "salt").update(secret).digest("hex")

      // Update client
      const updatedClient: Client = {
        ...client,
        secret,
        secretHash,
        updatedAt: new Date(),
      }

      // In a real implementation, this would update the database
      this.clients.set(id, updatedClient)

      // Emit client secret regenerated event
      this.eventEmitter.emit(OAuthEvent.CLIENT_SECRET_REGENERATED, {
        clientId: id,
        clientName: client.name,
        timestamp: new Date(),
      })

      return secret
    } catch (error) {
      logger.error("Error regenerating client secret", { error, id })
      throw error
    }
  }

  /**
   * Validate client secret
   * @param clientId Client ID
   * @param secret Client secret
   * @returns True if valid
   */
  async validateClientSecret(clientId: string, secret: string): Promise<boolean> {
    try {
      // Find client
      const client = await this.findById(clientId)
      if (!client) {
        return false
      }

      // Check if client is active
      if (!client.isActive) {
        return false
      }

      // Check if client has a secret hash
      if (!client.secretHash) {
        return false
      }

      // Hash the provided secret
      const hash = crypto.createHmac("sha256", oauthConfig.clientSecretSalt || "salt").update(secret).digest("hex")

      // Compare hashes
      return hash === client.secretHash
    } catch (error) {
      logger.error("Error validating client secret", { error, clientId })
      return false
    }
  }
}
