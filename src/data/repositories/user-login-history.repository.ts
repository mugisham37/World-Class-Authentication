import { Injectable } from '@tsed/di';
import { PrismaBaseRepository } from './prisma-base.repository';
import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { BaseRepository } from './base.repository';

/**
 * Repository for user login history
 */
@Injectable()
export class UserLoginHistoryRepository extends PrismaBaseRepository<any, string> {
  protected override readonly prisma: PrismaClient;
  protected readonly modelName: string = 'userLoginHistory';
  protected logger = logger;

  constructor(prisma: PrismaClient) {
    super(prisma);
    this.prisma = prisma;
  }

  /**
   * Create a new repository instance with a transaction client
   * @param tx The transaction client
   * @returns A new repository instance with the transaction client
   */
  protected withTransaction(tx: PrismaClient): BaseRepository<any, string> {
    const repo = new UserLoginHistoryRepository(tx);
    return repo;
  }

  /**
   * Find recent login history by user ID
   * @param userId User ID
   * @param limit Maximum number of records to return
   * @returns Login history records
   */
  async findRecentByUserId(userId: string, limit: number): Promise<any[]> {
    try {
      return await this.model.findMany({
        where: { userId },
        orderBy: { timestamp: 'desc' },
        take: limit,
      });
    } catch (error) {
      this.logger.error('Error finding recent login history by user ID', { error, userId, limit });
      return [];
    }
  }

  /**
   * Find login history by user ID since a specific date
   * @param userId User ID
   * @param since Date to find login history since
   * @returns Login history records
   */
  async findByUserId(userId: string, since: Date): Promise<any[]> {
    try {
      return await this.model.findMany({
        where: {
          userId,
          timestamp: {
            gte: since,
          },
        },
        orderBy: { timestamp: 'desc' },
      });
    } catch (error) {
      this.logger.error('Error finding login history by user ID', { error, userId, since });
      return [];
    }
  }

  /**
   * Find recent login history by IP address
   * @param ipAddress IP address
   * @param timeWindow Time window in milliseconds
   * @returns Login history records
   */
  async findRecentByIpAddress(ipAddress: string, timeWindow: number): Promise<any[]> {
    try {
      const since = new Date(Date.now() - timeWindow);
      return await this.model.findMany({
        where: {
          ipAddress,
          timestamp: {
            gte: since,
          },
        },
        orderBy: { timestamp: 'desc' },
      });
    } catch (error) {
      this.logger.error('Error finding recent login history by IP address', {
        error,
        ipAddress,
        timeWindow,
      });
      return [];
    }
  }

  /**
   * Find recent login history by device fingerprint
   * @param deviceFingerprint Device fingerprint
   * @param timeWindow Time window in milliseconds
   * @returns Login history records
   */
  async findRecentByDeviceFingerprint(
    deviceFingerprint: string,
    timeWindow: number
  ): Promise<any[]> {
    try {
      const since = new Date(Date.now() - timeWindow);
      return await this.model.findMany({
        where: {
          deviceFingerprint,
          timestamp: {
            gte: since,
          },
        },
        orderBy: { timestamp: 'desc' },
      });
    } catch (error) {
      this.logger.error('Error finding recent login history by device fingerprint', {
        error,
        deviceFingerprint,
        timeWindow,
      });
      return [];
    }
  }
}
