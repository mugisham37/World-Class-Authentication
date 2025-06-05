import { Injectable } from "@tsed/di"
import { PrismaBaseRepository } from "./prisma-base.repository"
import { PrismaClient } from "@prisma/client"
import { logger } from "../../infrastructure/logging/logger"
import { BaseRepository } from "./base.repository"

/**
 * Repository for user devices
 */
@Injectable()
export class UserDeviceRepository extends PrismaBaseRepository<any, string> {
  protected override readonly prisma: PrismaClient
  protected readonly modelName: string = "userDevice"
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
    const repo = new UserDeviceRepository(tx)
    return repo
  }

  /**
   * Find a device by user ID and device hash
   * @param userId User ID
   * @param deviceHash Device hash
   * @returns Device or null if not found
   */
  async findByUserIdAndHash(userId: string, deviceHash: string): Promise<any | null> {
    try {
      return await this.model.findFirst({
        where: {
          userId,
          deviceHash,
        },
      })
    } catch (error) {
      this.logger.error("Error finding device by user ID and hash", { error, userId, deviceHash })
      return null
    }
  }

  /**
   * Count users by device hash
   * @param deviceHash Device hash
   * @returns Number of users with this device
   */
  async countUsersByDeviceHash(deviceHash: string): Promise<number> {
    try {
      const devices = await this.model.findMany({
        where: {
          deviceHash,
        },
        select: {
          userId: true,
        },
      })

      // Get unique user IDs
      const uniqueUserIds = new Set(devices.map((device: { userId: string }) => device.userId))
      return uniqueUserIds.size
    } catch (error) {
      this.logger.error("Error counting users by device hash", { error, deviceHash })
      return 0
    }
  }

  /**
   * Update device last seen timestamp
   * @param deviceId Device ID
   * @returns Updated device
   */
  async updateLastSeen(deviceId: string): Promise<any> {
    try {
      return await this.model.update({
        where: {
          id: deviceId,
        },
        data: {
          lastSeen: new Date(),
        },
      })
    } catch (error) {
      this.logger.error("Error updating device last seen", { error, deviceId })
      return null
    }
  }
}
