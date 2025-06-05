import { Injectable } from '@tsed/di';
import { riskConfig } from '../../../config/risk.config';
import { logger } from '../../../infrastructure/logging/logger';
import type { UserLoginHistoryRepository } from '../../../data/repositories/user-login-history.repository';
import type { EventEmitter } from '../../../infrastructure/events/event-emitter';
import { RiskEvent } from '../risk-events';

/**
 * Time pattern service for risk assessment
 * Analyzes temporal patterns in user authentication
 */
@Injectable()
export class TimePatternService {
  constructor(
    private userLoginHistoryRepository: UserLoginHistoryRepository,
    private eventEmitter: EventEmitter
  ) {}

  /**
   * Assess risk based on time patterns
   * @param userId User ID (optional)
   * @param context Authentication context
   * @returns Risk score (0-100)
   */
  async assessRisk(userId: string | null, context: Record<string, any>): Promise<number> {
    try {
      // If no user ID, we can't analyze time patterns
      if (!userId) {
        return 0;
      }

      logger.debug('Starting time pattern risk assessment', { userId });

      // Get user's login history
      const loginHistory = await this.userLoginHistoryRepository.findRecentByUserId(
        userId,
        riskConfig.timePattern.windowHours
      );

      // If not enough history, return low risk
      if (!loginHistory || loginHistory.length < 3) {
        return 0;
      }

      // Initialize risk score
      let riskScore = 0;
      const riskFactors = riskConfig.timePattern.riskFactors;

      // Check for off-hours login
      const isOffHoursLogin = this.checkOffHoursLogin(loginHistory);
      if (isOffHoursLogin) {
        riskScore = Math.max(riskScore, riskFactors.offHoursLogin);

        // Emit off-hours login event
        this.eventEmitter.emit(RiskEvent.OFF_HOURS_LOGIN_DETECTED, {
          userId,
          timestamp: new Date(),
          loginTime: new Date(),
        });
      }

      // Check for irregular pattern
      const isIrregularPattern = this.checkIrregularPattern(loginHistory);
      if (isIrregularPattern) {
        riskScore = Math.max(riskScore, riskFactors.irregularPattern);

        // Emit irregular pattern event
        this.eventEmitter.emit(RiskEvent.IRREGULAR_PATTERN_DETECTED, {
          userId,
          timestamp: new Date(),
        });
      }

      // Check for high-frequency login
      const isHighFrequencyLogin = this.checkHighFrequencyLogin(loginHistory);
      if (isHighFrequencyLogin) {
        riskScore = Math.max(riskScore, riskFactors.highFrequencyLogin);

        // Emit high-frequency login event
        this.eventEmitter.emit(RiskEvent.HIGH_FREQUENCY_LOGIN_DETECTED, {
          userId,
          timestamp: new Date(),
          loginCount: loginHistory.length,
        });
      }

      // Check for account switching
      const isAccountSwitching = this.checkAccountSwitching(context);
      if (isAccountSwitching) {
        riskScore = Math.max(riskScore, riskFactors.accountSwitching);

        // Emit account switching event
        this.eventEmitter.emit(RiskEvent.ACCOUNT_SWITCHING_DETECTED, {
          userId,
          timestamp: new Date(),
          previousUserId: context.previousUserId,
        });
      }

      logger.debug('Time pattern risk assessment completed', { userId, riskScore });
      return riskScore;
    } catch (error) {
      logger.error('Error in time pattern risk assessment', { error, userId });
      return 0; // Default to no risk on error
    }
  }

  /**
   * Check if current login is during off-hours
   * @param loginHistory User's login history
   * @returns True if login is during off-hours
   */
  private checkOffHoursLogin(loginHistory: any[]): boolean {
    try {
      if (!loginHistory || loginHistory.length === 0) {
        return false;
      }

      // Get current time
      const now = new Date();
      const currentHour = now.getHours();
      const currentDay = now.getDay();

      // Define business hours (9 AM - 5 PM, Monday - Friday)
      const isBusinessHours =
        currentHour >= 9 && currentHour < 17 && currentDay >= 1 && currentDay <= 5;

      // If current login is during business hours, it's not off-hours
      if (isBusinessHours) {
        return false;
      }

      // Calculate typical login hours from history
      const loginHours = loginHistory
        .filter(login => login && login.timestamp)
        .map(login => login.timestamp.getHours());

      if (loginHours.length === 0) {
        return false;
      }

      // Calculate frequency of each hour
      const hourFrequency: Record<number, number> = {};
      loginHours.forEach(hour => {
        hourFrequency[hour] = (hourFrequency[hour] || 0) + 1;
      });

      // Calculate total logins
      const totalLogins = loginHours.length;

      // Check if current hour is unusual for this user
      const currentHourFrequency = hourFrequency[currentHour] || 0;
      const currentHourPercentage =
        totalLogins > 0 ? (currentHourFrequency / totalLogins) * 100 : 0;

      // If user rarely logs in at this hour (less than 10% of logins), consider it off-hours
      return currentHourPercentage < 10;
    } catch (error) {
      logger.error('Error checking off-hours login', { error });
      return false;
    }
  }

  /**
   * Check if current login follows an irregular pattern
   * @param loginHistory User's login history
   * @returns True if login pattern is irregular
   */
  private checkIrregularPattern(loginHistory: any[]): boolean {
    try {
      if (!loginHistory || loginHistory.length < 3) {
        return false;
      }

      // Get timestamps from login history
      const timestamps = loginHistory
        .filter(login => login && login.timestamp)
        .map(login => login.timestamp.getTime())
        .sort((a, b) => a - b);

      // If not enough timestamps, can't determine pattern
      if (timestamps.length < 3) {
        return false;
      }

      // Calculate intervals between logins
      const intervals: number[] = [];
      for (let i = 1; i < timestamps.length; i++) {
        intervals.push(timestamps[i] - timestamps[i - 1]);
      }

      // Calculate mean and standard deviation of intervals
      const meanInterval =
        intervals.reduce((sum, interval) => sum + interval, 0) / intervals.length;
      const variance =
        intervals.reduce((sum, interval) => sum + Math.pow(interval - meanInterval, 2), 0) /
        intervals.length;
      const stdDeviation = Math.sqrt(variance);

      // Calculate coefficient of variation (CV)
      // CV = (standard deviation / mean) * 100
      // Higher CV indicates more variability
      const coefficientOfVariation = (stdDeviation / meanInterval) * 100;

      // If CV is high (> 100%), pattern is irregular
      return coefficientOfVariation > 100;
    } catch (error) {
      logger.error('Error checking irregular pattern', { error });
      return false;
    }
  }

  /**
   * Check if current login is part of high-frequency login pattern
   * @param loginHistory User's login history
   * @returns True if login frequency is high
   */
  private checkHighFrequencyLogin(loginHistory: any[]): boolean {
    try {
      if (!loginHistory || loginHistory.length < 3) {
        return false;
      }

      // Get timestamps from login history
      const timestamps = loginHistory
        .filter(login => login && login.timestamp)
        .map(login => login.timestamp.getTime())
        .sort((a, b) => a - b);

      // If not enough timestamps, can't determine frequency
      if (timestamps.length < 3) {
        return false;
      }

      // Calculate time window in hours
      const timeWindowMs = timestamps[timestamps.length - 1] - timestamps[0];
      const timeWindowHours = timeWindowMs / (60 * 60 * 1000);

      if (timeWindowHours <= 0) {
        return false;
      }

      // Calculate login frequency (logins per hour)
      const frequency = timestamps.length / timeWindowHours;

      // If frequency is high (> 3 logins per hour), consider it high-frequency
      return frequency > 3;
    } catch (error) {
      logger.error('Error checking high-frequency login', { error });
      return false;
    }
  }

  /**
   * Check if current login is part of account switching pattern
   * @param context Authentication context
   * @returns True if account switching is detected
   */
  private checkAccountSwitching(context: Record<string, any>): boolean {
    try {
      if (!context) {
        return false;
      }

      // Check if context contains previous user ID
      if (!context.previousUserId || !context.previousLoginTime) {
        return false;
      }

      // Calculate time since previous login
      const previousLoginTime = new Date(context.previousLoginTime).getTime();
      const currentTime = Date.now();
      const timeSinceLastLoginMs = currentTime - previousLoginTime;
      const timeSinceLastLoginMinutes = timeSinceLastLoginMs / (60 * 1000);

      // If previous login was recent (< 30 minutes) and from a different user, consider it account switching
      return timeSinceLastLoginMinutes < 30;
    } catch (error) {
      logger.error('Error checking account switching', { error });
      return false;
    }
  }
}
