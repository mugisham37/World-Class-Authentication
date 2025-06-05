import { Injectable } from '@tsed/di';
import { riskConfig } from '../../../config/risk.config';
import { logger } from '../../../infrastructure/logging/logger';
import type { UserBehaviorProfile } from '../risk-types';
import type { UserBehaviorProfileRepository } from '../../../data/repositories/user-behavior-profile.repository';
import type { UserLoginHistoryRepository } from '../../../data/repositories/user-login-history.repository';
import type { UserActivityRepository } from '../../../data/repositories/user-activity.repository';
import type { EventEmitter } from '../../../infrastructure/events/event-emitter';
import { RiskEvent } from '../risk-events';

@Injectable()
export class UserBehaviorService {
  constructor(
    private userBehaviorProfileRepository: UserBehaviorProfileRepository,
    private userLoginHistoryRepository: UserLoginHistoryRepository,
    private userActivityRepository: UserActivityRepository,
    private eventEmitter: EventEmitter
  ) {}

  /**
   * Assess risk based on user behavior
   * @param userId User ID
   * @param context Authentication context
   * @returns Risk score (0-100)
   */
  async assessRisk(userId: string, context: Record<string, any>): Promise<number> {
    try {
      if (!userId) {
        logger.debug('No user ID provided for behavior risk assessment');
        return 20; // Low-moderate risk due to insufficient data
      }

      // Get user behavior profile
      const profile = await this.getUserBehaviorProfile(userId);

      // If we don't have enough data points, return a moderate risk score
      if (!profile || profile.dataPoints < riskConfig.userBehavior.minDataPoints) {
        return 20; // Low-moderate risk due to insufficient data
      }

      // Initialize risk score
      let riskScore = 0;
      const riskFactors = riskConfig.userBehavior.riskFactors;

      // Check for unusual login time
      const loginTimeScore = await this.assessLoginTime(userId, profile, context);
      if (loginTimeScore > 0) {
        riskScore = Math.max(riskScore, riskFactors.unusualLoginTime * (loginTimeScore / 100));
      }

      // Check for unusual login location
      const loginLocationScore = await this.assessLoginLocation(userId, profile, context);
      if (loginLocationScore > 0) {
        riskScore = Math.max(
          riskScore,
          riskFactors.unusualLoginLocation * (loginLocationScore / 100)
        );
      }

      // Check for unusual login frequency
      const loginFrequencyScore = await this.assessLoginFrequency(userId, profile, context);
      if (loginFrequencyScore > 0) {
        riskScore = Math.max(
          riskScore,
          riskFactors.unusualLoginFrequency * (loginFrequencyScore / 100)
        );
      }

      // Check for unusual activity pattern
      const activityPatternScore = await this.assessActivityPattern(userId, profile, context);
      if (activityPatternScore > 0) {
        riskScore = Math.max(
          riskScore,
          riskFactors.unusualActivityPattern * (activityPatternScore / 100)
        );
      }

      // Check for rapid account switching
      const accountSwitchingScore = await this.assessAccountSwitching(userId, context);
      if (accountSwitchingScore > 0) {
        riskScore = Math.max(
          riskScore,
          riskFactors.rapidAccountSwitching * (accountSwitchingScore / 100)
        );
      }

      // If any significant behavioral anomaly is detected, emit an event
      if (riskScore >= 50) {
        this.eventEmitter.emit(RiskEvent.BEHAVIOR_CHANGE_DETECTED, {
          userId,
          riskScore,
          factors: {
            loginTime: loginTimeScore,
            loginLocation: loginLocationScore,
            loginFrequency: loginFrequencyScore,
            activityPattern: activityPatternScore,
            accountSwitching: accountSwitchingScore,
          },
          context: {
            ipAddress: context.ipAddress,
            userAgent: context.userAgent,
          },
          timestamp: new Date(),
        });
      }

      logger.debug('User behavior risk assessment completed', {
        userId,
        riskScore,
        factors: {
          loginTime: loginTimeScore,
          loginLocation: loginLocationScore,
          loginFrequency: loginFrequencyScore,
          activityPattern: activityPatternScore,
          accountSwitching: accountSwitchingScore,
        },
      });

      return riskScore;
    } catch (error) {
      logger.error('Error assessing user behavior risk', { error, userId });
      return 20; // Default to low-moderate risk on error
    }
  }

  /**
   * Get or create user behavior profile
   * @param userId User ID
   * @returns User behavior profile
   */
  private async getUserBehaviorProfile(userId: string): Promise<UserBehaviorProfile | null> {
    try {
      if (!userId) {
        return null;
      }

      // Try to get existing profile
      let profile = await this.userBehaviorProfileRepository.findByUserId(userId);

      // If profile doesn't exist or is outdated, generate a new one
      if (!profile || this.isProfileOutdated(profile)) {
        profile = await this.generateUserBehaviorProfile(userId);
      }

      return profile;
    } catch (error) {
      logger.error('Error getting user behavior profile', { error, userId });
      return null;
    }
  }

  /**
   * Check if a profile is outdated
   * @param profile User behavior profile
   * @returns True if profile is outdated
   */
  private isProfileOutdated(profile: UserBehaviorProfile): boolean {
    if (!profile || !profile.lastUpdated) {
      return true;
    }

    // Check if profile was updated more than 24 hours ago
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    return profile.lastUpdated < oneDayAgo;
  }

  /**
   * Generate a new user behavior profile
   * @param userId User ID
   * @returns Generated user behavior profile
   */
  private async generateUserBehaviorProfile(userId: string): Promise<UserBehaviorProfile | null> {
    try {
      if (!userId) {
        return null;
      }

      // Get login history
      const loginHistory = await this.userLoginHistoryRepository.findByUserId(
        userId,
        new Date(Date.now() - riskConfig.userBehavior.analysisWindow * 1000)
      );

      // If we don't have enough data, return null
      if (!loginHistory || loginHistory.length < riskConfig.userBehavior.minDataPoints) {
        return null;
      }

      // Get user activity
      const userActivity = await this.userActivityRepository.findByUserId(
        userId,
        new Date(Date.now() - riskConfig.userBehavior.analysisWindow * 1000)
      );

      // Initialize profile
      const profile: UserBehaviorProfile = {
        userId,
        loginTimes: {
          hourDistribution: new Array(24).fill(0),
          dayDistribution: new Array(7).fill(0),
        },
        loginLocations: {
          countries: {},
          regions: {},
          cities: {},
          coordinates: [],
        },
        devices: {
          browsers: {},
          operatingSystems: {},
          deviceTypes: {},
        },
        activityPatterns: {
          sessionDuration: {
            mean: 0,
            stdDev: 0,
          },
          actionsPerSession: {
            mean: 0,
            stdDev: 0,
          },
          actionTypes: {},
        },
        lastUpdated: new Date(),
        dataPoints: loginHistory.length,
      };

      // Process login times
      for (const login of loginHistory) {
        if (!login.timestamp) continue;

        const date = login.timestamp;

        // Hour distribution (0-23)
        const hour = date.getHours();
        profile.loginTimes.hourDistribution[hour]++;

        // Day distribution (0-6, where 0 is Sunday)
        const day = date.getDay();
        profile.loginTimes.dayDistribution[day]++;

        // Login locations
        if (login.countryCode) {
          profile.loginLocations.countries[login.countryCode] =
            (profile.loginLocations.countries[login.countryCode] || 0) + 1;
        }

        if (login.regionCode) {
          profile.loginLocations.regions[login.regionCode] =
            (profile.loginLocations.regions[login.regionCode] || 0) + 1;
        }

        if (login.city) {
          profile.loginLocations.cities[login.city] =
            (profile.loginLocations.cities[login.city] || 0) + 1;
        }

        if (login.latitude && login.longitude) {
          profile.loginLocations.coordinates.push([login.latitude, login.longitude]);
        }

        // Devices
        if (login.browser) {
          profile.devices.browsers[login.browser] =
            (profile.devices.browsers[login.browser] || 0) + 1;
        }

        if (login.os) {
          profile.devices.operatingSystems[login.os] =
            (profile.devices.operatingSystems[login.os] || 0) + 1;
        }

        if (login.deviceType) {
          profile.devices.deviceTypes[login.deviceType] =
            (profile.devices.deviceTypes[login.deviceType] || 0) + 1;
        }
      }

      // Process activity patterns
      if (userActivity && userActivity.length > 0) {
        // Group activities by session
        const sessions = this.groupActivitiesBySessions(userActivity);

        // Calculate session durations
        const sessionDurations: number[] = [];
        const actionsPerSession: number[] = [];

        for (const session of sessions) {
          if (session.length > 0) {
            const firstActivity = session[0];
            const lastActivity = session[session.length - 1];

            if (firstActivity.timestamp && lastActivity.timestamp) {
              const duration =
                (lastActivity.timestamp.getTime() - firstActivity.timestamp.getTime()) / 1000 / 60; // minutes
              sessionDurations.push(duration);
            }

            actionsPerSession.push(session.length);

            // Count action types
            for (const activity of session) {
              if (activity.actionType) {
                profile.activityPatterns.actionTypes[activity.actionType] =
                  (profile.activityPatterns.actionTypes[activity.actionType] || 0) + 1;
              }
            }
          }
        }

        // Calculate mean and standard deviation for session duration
        if (sessionDurations.length > 0) {
          profile.activityPatterns.sessionDuration = this.calculateStats(sessionDurations);
        }

        // Calculate mean and standard deviation for actions per session
        if (actionsPerSession.length > 0) {
          profile.activityPatterns.actionsPerSession = this.calculateStats(actionsPerSession);
        }
      }

      // Normalize distributions
      this.normalizeDistribution(profile.loginTimes.hourDistribution);
      this.normalizeDistribution(profile.loginTimes.dayDistribution);

      // Save profile
      return await this.userBehaviorProfileRepository.createOrUpdate(profile);
    } catch (error) {
      logger.error('Error generating user behavior profile', { error, userId });
      return null;
    }
  }

  /**
   * Group user activities into sessions
   * @param activities User activities
   * @returns Activities grouped by session
   */
  private groupActivitiesBySessions(activities: any[]): any[][] {
    if (!activities || activities.length === 0) {
      return [];
    }

    // Sort activities by timestamp
    const sortedActivities = [...activities].sort((a, b) => {
      if (!a.timestamp || !b.timestamp) return 0;
      return a.timestamp.getTime() - b.timestamp.getTime();
    });

    const sessions: any[][] = [];
    let currentSession: any[] = [];

    for (const activity of sortedActivities) {
      if (currentSession.length === 0) {
        // Start a new session
        currentSession.push(activity);
      } else {
        const lastActivity = currentSession[currentSession.length - 1];
        if (!lastActivity.timestamp || !activity.timestamp) {
          currentSession.push(activity);
          continue;
        }

        const timeDiff =
          (activity.timestamp.getTime() - lastActivity.timestamp.getTime()) / 1000 / 60; // minutes

        if (timeDiff <= 30) {
          // Add to current session if within 30 minutes
          currentSession.push(activity);
        } else {
          // Start a new session
          sessions.push(currentSession);
          currentSession = [activity];
        }
      }
    }

    // Add the last session
    if (currentSession.length > 0) {
      sessions.push(currentSession);
    }

    return sessions;
  }

  /**
   * Calculate mean and standard deviation
   * @param values Array of values
   * @returns Mean and standard deviation
   */
  private calculateStats(values: number[]): { mean: number; stdDev: number } {
    if (!values || values.length === 0) {
      return { mean: 0, stdDev: 0 };
    }

    const mean = values.reduce((sum, value) => sum + value, 0) / values.length;

    const squaredDiffs = values.map(value => Math.pow(value - mean, 2));
    const variance = squaredDiffs.reduce((sum, value) => sum + value, 0) / values.length;
    const stdDev = Math.sqrt(variance);

    return { mean, stdDev };
  }

  /**
   * Normalize a distribution to sum to 1
   * @param distribution Distribution array
   */
  private normalizeDistribution(distribution: number[]): void {
    if (!distribution || distribution.length === 0) {
      return;
    }

    const sum = distribution.reduce((sum, value) => sum + value, 0);

    if (sum > 0) {
      for (let i = 0; i < distribution.length; i++) {
        distribution[i] = distribution[i] / sum;
      }
    }
  }

  /**
   * Assess login time risk
   * @param userId User ID
   * @param profile User behavior profile
   * @param context Authentication context
   * @returns Risk score (0-100)
   */
  private async assessLoginTime(
    userId: string,
    profile: UserBehaviorProfile,
    context: Record<string, any>
  ): Promise<number> {
    try {
      if (!profile || !profile.loginTimes) {
        return 0;
      }

      const now = new Date();
      const hour = now.getHours();
      const day = now.getDay();

      // Get the probability of login at this hour and day
      const hourProb = profile.loginTimes.hourDistribution[hour];
      const dayProb = profile.loginTimes.dayDistribution[day];

      // Calculate combined probability
      const combinedProb = hourProb * dayProb;

      // Convert to risk score (lower probability = higher risk)
      let riskScore = 0;

      if (combinedProb === 0) {
        // Never logged in at this time before
        riskScore = 100;
      } else if (combinedProb < 0.01) {
        // Very rare login time
        riskScore = 80;
      } else if (combinedProb < 0.05) {
        // Uncommon login time
        riskScore = 60;
      } else if (combinedProb < 0.1) {
        // Somewhat unusual login time
        riskScore = 40;
      } else if (combinedProb < 0.2) {
        // Slightly unusual login time
        riskScore = 20;
      }

      return riskScore;
    } catch (error) {
      logger.error('Error assessing login time risk', { error, userId });
      return 0;
    }
  }

  /**
   * Assess login location risk
   * @param userId User ID
   * @param profile User behavior profile
   * @param context Authentication context
   * @returns Risk score (0-100)
   */
  private async assessLoginLocation(
    userId: string,
    profile: UserBehaviorProfile,
    context: Record<string, any>
  ): Promise<number> {
    try {
      if (!profile || !profile.loginLocations || !context) {
        return 0;
      }

      // Get country, region, city from context
      const { countryCode, regionCode, city } = context;

      if (!countryCode) {
        return 0; // No location data
      }

      // Check if user has logged in from this country before
      const countryProb = profile.loginLocations.countries[countryCode] || 0;

      // Check if user has logged in from this region before
      const regionProb = regionCode ? profile.loginLocations.regions[regionCode] || 0 : 0;

      // Check if user has logged in from this city before
      const cityProb = city ? profile.loginLocations.cities[city] || 0 : 0;

      // Calculate risk score
      let riskScore = 0;

      if (countryProb === 0) {
        // Never logged in from this country before
        riskScore = 100;
      } else if (regionProb === 0) {
        // Never logged in from this region before
        riskScore = 80;
      } else if (cityProb === 0) {
        // Never logged in from this city before
        riskScore = 60;
      } else {
        // Calculate how common this location is
        const totalLogins = profile.dataPoints;
        const countryFreq = countryProb / totalLogins;
        const regionFreq = regionProb / totalLogins;
        const cityFreq = cityProb / totalLogins;

        // Weighted average of frequencies (more weight to more specific locations)
        const weightedFreq = countryFreq * 0.2 + regionFreq * 0.3 + cityFreq * 0.5;

        if (weightedFreq < 0.05) {
          // Very rare location
          riskScore = 50;
        } else if (weightedFreq < 0.1) {
          // Uncommon location
          riskScore = 30;
        } else if (weightedFreq < 0.2) {
          // Somewhat unusual location
          riskScore = 20;
        }
      }

      return riskScore;
    } catch (error) {
      logger.error('Error assessing login location risk', { error, userId });
      return 0;
    }
  }

  /**
   * Assess login frequency risk
   * @param userId User ID
   * @param profile User behavior profile
   * @param context Authentication context
   * @returns Risk score (0-100)
   */
  private async assessLoginFrequency(
    userId: string,
    profile: UserBehaviorProfile,
    context: Record<string, any>
  ): Promise<number> {
    try {
      if (!userId) {
        return 0;
      }

      // Get recent logins
      const recentLogins = await this.userLoginHistoryRepository.findRecentByUserId(userId, 10);

      if (!recentLogins || recentLogins.length < 2) {
        return 0; // Not enough data
      }

      // Calculate time since last login
      const lastLogin = recentLogins[0];
      if (!lastLogin.timestamp) {
        return 0;
      }

      const timeSinceLastLogin = (Date.now() - lastLogin.timestamp.getTime()) / 1000 / 60 / 60; // hours

      // Calculate average time between logins
      let totalTimeBetween = 0;
      let validIntervals = 0;

      for (let i = 1; i < recentLogins.length; i++) {
        if (recentLogins[i - 1].timestamp && recentLogins[i].timestamp) {
          const timeBetween =
            (recentLogins[i - 1].timestamp.getTime() - recentLogins[i].timestamp.getTime()) /
            1000 /
            60 /
            60; // hours
          totalTimeBetween += timeBetween;
          validIntervals++;
        }
      }

      if (validIntervals === 0) {
        return 0;
      }

      const avgTimeBetween = totalTimeBetween / validIntervals;

      // Calculate standard deviation
      let totalSquaredDiff = 0;
      let validDiffs = 0;

      for (let i = 1; i < recentLogins.length; i++) {
        if (recentLogins[i - 1].timestamp && recentLogins[i].timestamp) {
          const timeBetween =
            (recentLogins[i - 1].timestamp.getTime() - recentLogins[i].timestamp.getTime()) /
            1000 /
            60 /
            60; // hours
          totalSquaredDiff += Math.pow(timeBetween - avgTimeBetween, 2);
          validDiffs++;
        }
      }

      if (validDiffs === 0) {
        return 0;
      }

      const stdDev = Math.sqrt(totalSquaredDiff / validDiffs);

      // Calculate z-score for current login
      const zScore = Math.abs((timeSinceLastLogin - avgTimeBetween) / (stdDev || 1)); // Avoid division by zero

      // Convert z-score to risk score
      let riskScore = 0;

      if (zScore > 3) {
        // Very unusual timing (>3 standard deviations)
        riskScore = 80;
      } else if (zScore > 2) {
        // Unusual timing (>2 standard deviations)
        riskScore = 60;
      } else if (zScore > 1.5) {
        // Somewhat unusual timing (>1.5 standard deviations)
        riskScore = 40;
      } else if (zScore > 1) {
        // Slightly unusual timing (>1 standard deviation)
        riskScore = 20;
      }

      return riskScore;
    } catch (error) {
      logger.error('Error assessing login frequency risk', { error, userId });
      return 0;
    }
  }

  /**
   * Assess activity pattern risk
   * @param userId User ID
   * @param profile User behavior profile
   * @param context Authentication context
   * @returns Risk score (0-100)
   */
  private async assessActivityPattern(
    userId: string,
    profile: UserBehaviorProfile,
    context: Record<string, any>
  ): Promise<number> {
    try {
      if (!profile || !profile.devices || !context) {
        return 0;
      }

      // For login assessment, we don't have activity data yet
      // This would be more useful for continuous authentication

      // Check if device type matches usual patterns
      const deviceType = context.deviceType;

      if (deviceType && profile.devices.deviceTypes) {
        const totalDevices = Object.values(profile.devices.deviceTypes).reduce(
          (sum, count) => sum + Number(count),
          0
        );
        if (totalDevices === 0) {
          return 0;
        }

        const deviceTypeCount = profile.devices.deviceTypes[deviceType] || 0;
        const deviceTypeFreq = deviceTypeCount / totalDevices;

        if (deviceTypeFreq === 0) {
          // Never used this device type before
          return 60;
        } else if (deviceTypeFreq < 0.1) {
          // Rarely used device type
          return 40;
        } else if (deviceTypeFreq < 0.2) {
          // Uncommonly used device type
          return 20;
        }
      }

      return 0;
    } catch (error) {
      logger.error('Error assessing activity pattern risk', { error, userId });
      return 0;
    }
  }

  /**
   * Assess account switching risk
   * @param userId User ID
   * @param context Authentication context
   * @returns Risk score (0-100)
   */
  private async assessAccountSwitching(
    userId: string,
    context: Record<string, any>
  ): Promise<number> {
    try {
      if (!userId || !context) {
        return 0;
      }

      // Check if this IP or device has been used for multiple accounts recently
      const ipAddress = context.ipAddress;
      const deviceFingerprint = context.deviceFingerprint;

      if (!ipAddress && !deviceFingerprint) {
        return 0; // No data to check
      }

      let riskScore = 0;

      // Check IP address
      if (ipAddress) {
        // Get recent logins from this IP
        const recentLoginsFromIp = await this.userLoginHistoryRepository.findRecentByIpAddress(
          ipAddress,
          24 * 60 * 60 * 1000
        ); // 24 hours

        if (recentLoginsFromIp && recentLoginsFromIp.length > 0) {
          // Count unique users
          const uniqueUsers = new Set(
            recentLoginsFromIp.map(login => login.userId).filter(Boolean)
          );

          // Exclude current user
          uniqueUsers.delete(userId);

          const otherUserCount = uniqueUsers.size;

          if (otherUserCount > 5) {
            // Many different accounts from same IP
            riskScore = Math.max(riskScore, 80);
          } else if (otherUserCount > 2) {
            // Several different accounts from same IP
            riskScore = Math.max(riskScore, 60);
          } else if (otherUserCount > 0) {
            // At least one other account from same IP
            riskScore = Math.max(riskScore, 30);
          }
        }
      }

      // Check device fingerprint
      if (deviceFingerprint) {
        // Get recent logins from this device
        const recentLoginsFromDevice =
          await this.userLoginHistoryRepository.findRecentByDeviceFingerprint(
            deviceFingerprint,
            24 * 60 * 60 * 1000 // 24 hours
          );

        if (recentLoginsFromDevice && recentLoginsFromDevice.length > 0) {
          // Count unique users
          const uniqueUsers = new Set(
            recentLoginsFromDevice.map(login => login.userId).filter(Boolean)
          );

          // Exclude current user
          uniqueUsers.delete(userId);

          const otherUserCount = uniqueUsers.size;

          if (otherUserCount > 3) {
            // Many different accounts from same device
            riskScore = Math.max(riskScore, 90);
          } else if (otherUserCount > 1) {
            // Several different accounts from same device
            riskScore = Math.max(riskScore, 70);
          } else if (otherUserCount > 0) {
            // One other account from same device
            riskScore = Math.max(riskScore, 40);
          }
        }
      }

      return riskScore;
    } catch (error) {
      logger.error('Error assessing account switching risk', { error, userId });
      return 0;
    }
  }

  /**
   * Update user behavior profile with new login data
   * @param userId User ID
   * @param loginData Login data
   */
  async updateProfileWithLogin(userId: string, loginData: Record<string, any>): Promise<void> {
    try {
      if (!userId || !loginData) {
        return;
      }

      // Get existing profile
      let profile = await this.userBehaviorProfileRepository.findByUserId(userId);

      // If profile doesn't exist, generate a new one
      if (!profile) {
        profile = await this.generateUserBehaviorProfile(userId);

        // If we still couldn't generate a profile, return
        if (!profile) {
          return;
        }
      }

      // Update profile with new login data
      const now = new Date();

      // Update login times
      const hour = now.getHours();
      const day = now.getDay();

      profile.loginTimes.hourDistribution[hour]++;
      profile.loginTimes.dayDistribution[day]++;

      // Update login locations
      if (loginData.countryCode) {
        profile.loginLocations.countries[loginData.countryCode] =
          (profile.loginLocations.countries[loginData.countryCode] || 0) + 1;
      }

      if (loginData.regionCode) {
        profile.loginLocations.regions[loginData.regionCode] =
          (profile.loginLocations.regions[loginData.regionCode] || 0) + 1;
      }

      if (loginData.city) {
        profile.loginLocations.cities[loginData.city] =
          (profile.loginLocations.cities[loginData.city] || 0) + 1;
      }

      if (loginData.latitude && loginData.longitude) {
        profile.loginLocations.coordinates.push([loginData.latitude, loginData.longitude]);
      }

      // Update devices
      if (loginData.browser) {
        profile.devices.browsers[loginData.browser] =
          (profile.devices.browsers[loginData.browser] || 0) + 1;
      }

      if (loginData.os) {
        profile.devices.operatingSystems[loginData.os] =
          (profile.devices.operatingSystems[loginData.os] || 0) + 1;
      }

      if (loginData.deviceType) {
        profile.devices.deviceTypes[loginData.deviceType] =
          (profile.devices.deviceTypes[loginData.deviceType] || 0) + 1;
      }

      // Update data points and last updated
      profile.dataPoints++;
      profile.lastUpdated = now;

      // Normalize distributions
      this.normalizeDistribution(profile.loginTimes.hourDistribution);
      this.normalizeDistribution(profile.loginTimes.dayDistribution);

      // Save updated profile
      await this.userBehaviorProfileRepository.createOrUpdate(profile);
    } catch (error) {
      logger.error('Error updating user behavior profile with login', { error, userId });
    }
  }
}
