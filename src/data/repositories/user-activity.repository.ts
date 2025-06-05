import { Injectable } from "@tsed/di"
import { PrismaBaseRepository } from "./prisma-base.repository"
import { PrismaClient } from "@prisma/client"
import { logger } from "../../infrastructure/logging/logger"
import { BaseRepository } from "./base.repository"

/**
 * Repository for user activities
 */
@Injectable()
export class UserActivityRepository extends PrismaBaseRepository<any, string> {
  protected override readonly prisma: PrismaClient
  protected readonly modelName: string = "userActivity"
  protected logger = logger

  constructor(prisma: PrismaClient) {
    super(prisma)
    this.prisma = prisma
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected withTransaction(tx: PrismaClient): BaseRepository<any, string> {
    const repo = new UserActivityRepository(tx)
    return repo
  }

  /**
   * Find activities by user ID and date range
   * @param userId User ID
   * @param startDate Start date (optional)
   * @param endDate End date (optional)
   * @returns User activities
   */
  async findByUserId(userId: string, startDate?: Date, endDate?: Date): Promise<any[]> {
    try {
      const where: any = {
        userId,
      }

      if (startDate || endDate) {
        where.timestamp = {}
        if (startDate) {
          where.timestamp.gte = startDate
        }
        if (endDate) {
          where.timestamp.lte = endDate
        }
      }

      return await this.model.findMany({
        where,
        orderBy: {
          timestamp: "desc",
        },
      })
    } catch (error) {
      this.logger.error("Error finding activities by user ID", { error, userId })
      return []
    }
  }

  /**
   * Find recent activities by user ID
   * @param userId User ID
   * @param limit Maximum number of activities to return
   * @returns Recent user activities
   */
  async findRecentByUserId(userId: string, limit: number = 10): Promise<any[]> {
    try {
      return await this.model.findMany({
        where: {
          userId,
        },
        orderBy: {
          timestamp: "desc",
        },
        take: limit,
      })
    } catch (error) {
      this.logger.error("Error finding recent activities by user ID", { error, userId })
      return []
    }
  }

  /**
   * Find activities by session ID
   * @param sessionId Session ID
   * @returns User activities for the session
   */
  async findBySessionId(sessionId: string): Promise<any[]> {
    try {
      return await this.model.findMany({
        where: {
          sessionId,
        },
        orderBy: {
          timestamp: "desc",
        },
      })
    } catch (error) {
      this.logger.error("Error finding activities by session ID", { error, sessionId })
      return []
    }
  }

  /**
   * Find activities by action type
   * @param userId User ID
   * @param actionType Action type
   * @param limit Maximum number of activities to return
   * @returns User activities of the specified type
   */
  async findByActionType(userId: string, actionType: string, limit: number = 10): Promise<any[]> {
    try {
      return await this.model.findMany({
        where: {
          userId,
          actionType,
        },
        orderBy: {
          timestamp: "desc",
        },
        take: limit,
      })
    } catch (error) {
      this.logger.error("Error finding activities by action type", { error, userId, actionType })
      return []
    }
  }

  /**
   * Count activities by user ID and action type
   * @param userId User ID
   * @param actionType Action type
   * @param startDate Start date (optional)
   * @param endDate End date (optional)
   * @returns Count of activities
   */
  async countByActionType(userId: string, actionType: string, startDate?: Date, endDate?: Date): Promise<number> {
    try {
      const where: any = {
        userId,
        actionType,
      }

      if (startDate || endDate) {
        where.timestamp = {}
        if (startDate) {
          where.timestamp.gte = startDate
        }
        if (endDate) {
          where.timestamp.lte = endDate
        }
      }

      return await this.model.count({
        where,
      })
    } catch (error) {
      this.logger.error("Error counting activities by action type", { error, userId, actionType })
      return 0
    }
  }
}
