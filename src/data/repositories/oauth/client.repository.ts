import { Injectable } from "@tsed/di"
import { PrismaBaseRepository } from "../../repositories/prisma-base.repository"
import { PrismaClient } from "@prisma/client"
import { BaseRepository } from "../../repositories/base.repository"
import { OAuthClient, CreateOAuthClientData, UpdateOAuthClientData } from "../../models/oauth-client.model"
import { initPrismaClientWithOAuthClient } from "../../prisma/oauth-client.prisma"

/**
 * OAuth client repository
 * Handles CRUD operations for OAuth clients
 */
@Injectable()
export class ClientRepository extends PrismaBaseRepository<OAuthClient, string> {
  /**
   * Protected model name for Prisma
   */
  protected readonly modelName = "oauthClient"

  /**
   * Constructor
   * @param prisma Prisma client
   */
  constructor(prisma: PrismaClient) {
    // Initialize the Prisma client with the OAuthClient model
    const prismaWithOAuthClient = initPrismaClientWithOAuthClient(prisma)
    super(prismaWithOAuthClient)
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected withTransaction(tx: PrismaClient): BaseRepository<OAuthClient, string> {
    // Initialize the transaction client with the OAuthClient model
    const txWithOAuthClient = initPrismaClientWithOAuthClient(tx)
    return new ClientRepository(txWithOAuthClient)
  }

  /**
   * Find client by ID
   * @param id Client ID
   * @returns Client or null if not found
   */
  override async findById(id: string): Promise<OAuthClient | null> {
    return this.model.findUnique({
      where: { id },
    }) as Promise<OAuthClient | null>
  }

  /**
   * Create a new client
   * @param client Client data
   * @returns Created client
   */
  override async create(client: CreateOAuthClientData): Promise<OAuthClient> {
    return this.model.create({
      data: client,
    }) as Promise<OAuthClient>
  }

  /**
   * Update client
   * @param id Client ID
   * @param data Client data
   * @returns Updated client
   */
  override async update(id: string, data: UpdateOAuthClientData): Promise<OAuthClient> {
    return this.model.update({
      where: { id },
      data,
    }) as Promise<OAuthClient>
  }

  /**
   * Delete client
   * @param id Client ID
   * @returns True if the client was deleted, false otherwise
   */
  override async delete(id: string): Promise<boolean> {
    try {
      await this.model.delete({
        where: { id },
      })
      return true
    } catch (error) {
      if (error instanceof Error && error.message.includes('Record to delete does not exist')) {
        return false
      }
      throw error
    }
  }

  /**
   * Find clients by user ID
   * @param userId User ID
   * @returns Clients
   */
  async findByUserId(userId: string): Promise<OAuthClient[]> {
    return this.model.findMany({
      where: { userId },
    }) as Promise<OAuthClient[]>
  }

  /**
   * Find client by client ID
   * @param clientId Client ID (not the primary key)
   * @returns Client or null if not found
   */
  async findByClientId(clientId: string): Promise<OAuthClient | null> {
    return this.model.findFirst({
      where: { clientId },
    }) as Promise<OAuthClient | null>
  }
}
