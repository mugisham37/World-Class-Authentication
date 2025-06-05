import { Injectable } from '@tsed/di';
import { PrismaBaseRepository } from './prisma-base.repository';
import { PrismaClient } from '@prisma/client';
import { logger } from '../../infrastructure/logging/logger';
import { BaseRepository } from './base.repository';
import type { UserBehaviorProfile } from '../../core/risk/risk-types';

/**
 * Repository for user behavior profiles
 */
@Injectable()
export class UserBehaviorProfileRepository extends PrismaBaseRepository<any, string> {
  protected override readonly prisma: PrismaClient;
  protected readonly modelName: string = 'userBehaviorProfile';
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
    const repo = new UserBehaviorProfileRepository(tx);
    return repo;
  }

  /**
   * Find a behavior profile by user ID
   * @param userId User ID
   * @returns Behavior profile or null if not found
   */
  async findByUserId(userId: string): Promise<UserBehaviorProfile | null> {
    try {
      const profile = await this.model.findFirst({
        where: {
          userId,
        },
      });

      if (!profile) {
        return null;
      }

      // Parse JSON fields
      return {
        ...profile,
        loginTimes: JSON.parse(profile.loginTimes as string),
        loginLocations: JSON.parse(profile.loginLocations as string),
        devices: JSON.parse(profile.devices as string),
        activityPatterns: JSON.parse(profile.activityPatterns as string),
        lastUpdated: new Date(profile.lastUpdated),
        dataPoints: profile.dataPoints,
      } as UserBehaviorProfile;
    } catch (error) {
      this.logger.error('Error finding behavior profile by user ID', { error, userId });
      return null;
    }
  }

  /**
   * Create or update a behavior profile
   * @param profile Behavior profile
   * @returns Created or updated profile
   */
  async createOrUpdate(profile: UserBehaviorProfile): Promise<UserBehaviorProfile> {
    try {
      // Prepare data for storage (convert objects to JSON)
      const data = {
        userId: profile.userId,
        loginTimes: JSON.stringify(profile.loginTimes),
        loginLocations: JSON.stringify(profile.loginLocations),
        devices: JSON.stringify(profile.devices),
        activityPatterns: JSON.stringify(profile.activityPatterns),
        lastUpdated: profile.lastUpdated,
        dataPoints: profile.dataPoints,
      };

      // Check if profile exists
      const existingProfile = await this.model.findFirst({
        where: {
          userId: profile.userId,
        },
      });

      if (existingProfile) {
        // Update existing profile
        const updated = await this.model.update({
          where: {
            id: existingProfile.id,
          },
          data,
        });

        return {
          ...updated,
          loginTimes: profile.loginTimes,
          loginLocations: profile.loginLocations,
          devices: profile.devices,
          activityPatterns: profile.activityPatterns,
        } as UserBehaviorProfile;
      } else {
        // Create new profile
        const created = await this.model.create({
          data,
        });

        return {
          ...created,
          loginTimes: profile.loginTimes,
          loginLocations: profile.loginLocations,
          devices: profile.devices,
          activityPatterns: profile.activityPatterns,
        } as UserBehaviorProfile;
      }
    } catch (error) {
      this.logger.error('Error creating or updating behavior profile', {
        error,
        userId: profile.userId,
      });
      throw error;
    }
  }
}
