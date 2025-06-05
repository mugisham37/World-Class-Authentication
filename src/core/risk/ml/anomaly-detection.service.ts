import { Injectable } from '@tsed/di';
import { logger } from '../../../infrastructure/logging/logger';
import type { FeatureExtractionService } from './feature-extraction.service';
import type { RiskAssessmentRepository } from '../../../data/repositories/risk-assessment.repository';
import type { UserLoginHistoryRepository } from '../../../data/repositories/user-login-history.repository';
import type { EventEmitter } from '../../../infrastructure/events/event-emitter';
import { RiskEvent } from '../risk-events';

/**
 * Anomaly detection service for risk assessment
 * Detects anomalies in user authentication behavior
 */
@Injectable()
export class AnomalyDetectionService {
  constructor(
    private featureExtractionService: FeatureExtractionService,
    private riskAssessmentRepository: RiskAssessmentRepository,
    private userLoginHistoryRepository: UserLoginHistoryRepository,
    private eventEmitter: EventEmitter
  ) {}

  /**
   * Detect anomalies in user authentication behavior
   * @param userId User ID
   * @param context Authentication context
   * @returns Anomaly detection results with scores
   */
  async detectAnomalies(
    userId: string,
    context: Record<string, any>
  ): Promise<Record<string, any>> {
    try {
      logger.debug('Starting anomaly detection', { userId });

      // Extract features for the current authentication attempt
      const features = await this.featureExtractionService.extractAuthenticationFeatures(
        userId,
        context
      );

      // Get user's historical authentication data
      const loginHistory = await this.userLoginHistoryRepository.findRecentByUserId(userId, 50);

      // Get previous risk assessments
      const riskAssessments = await this.riskAssessmentRepository.findRecentByUserId(userId, 20);

      // Initialize anomaly scores
      const anomalyScores: Record<string, number> = {
        temporal_anomaly: 0,
        location_anomaly: 0,
        device_anomaly: 0,
        behavior_anomaly: 0,
        overall_anomaly: 0,
      };

      // Detect temporal anomalies
      anomalyScores['temporal_anomaly'] = await this.detectTemporalAnomalies(
        features,
        loginHistory
      );

      // Detect location anomalies
      anomalyScores['location_anomaly'] = await this.detectLocationAnomalies(
        features,
        loginHistory
      );

      // Detect device anomalies
      anomalyScores['device_anomaly'] = await this.detectDeviceAnomalies(features, loginHistory);

      // Detect behavior anomalies
      anomalyScores['behavior_anomaly'] = await this.detectBehaviorAnomalies(
        features,
        riskAssessments
      );

      // Calculate overall anomaly score
      anomalyScores['overall_anomaly'] = this.calculateOverallAnomalyScore(anomalyScores);

      // Emit anomaly detection event if significant anomalies detected
      if (anomalyScores['overall_anomaly'] > 70) {
        this.eventEmitter.emit(RiskEvent.ANOMALY_DETECTED, {
          userId,
          anomalyScores,
          features,
          context: this.sanitizeContext(context),
          timestamp: new Date(),
        });
      }

      logger.debug('Anomaly detection completed', {
        userId,
        overallScore: anomalyScores['overall_anomaly'],
      });

      return {
        anomalyScores,
        anomalyDetails: this.generateAnomalyDetails(anomalyScores, features),
      };
    } catch (error) {
      logger.error('Error detecting anomalies', { error, userId });
      return {
        anomalyScores: {
          temporal_anomaly: 0,
          location_anomaly: 0,
          device_anomaly: 0,
          behavior_anomaly: 0,
          overall_anomaly: 0,
        },
        anomalyDetails: {},
      };
    }
  }

  /**
   * Detect temporal anomalies in authentication behavior
   * @param features Current authentication features
   * @param loginHistory User's login history
   * @returns Temporal anomaly score (0-100)
   */
  private async detectTemporalAnomalies(
    features: Record<string, any>,
    loginHistory: any[]
  ): Promise<number> {
    try {
      if (loginHistory.length < 5) {
        return 0; // Not enough data for reliable detection
      }

      let anomalyScore = 0;

      // Check login time anomaly
      if (features['login_time_variance'] < 2) {
        // User typically logs in at consistent times
        const now = new Date();
        const currentHour = now.getHours();

        // Calculate typical login hours
        const loginHours = loginHistory
          .filter(login => login.timestamp)
          .map(login => login.timestamp.getHours());

        // Calculate mean and standard deviation of login hours
        const meanHour = this.calculateMean(loginHours);
        const stdHour = this.calculateStandardDeviation(loginHours);

        // Calculate z-score for current hour
        const zScore = Math.abs((currentHour - meanHour) / (stdHour || 1));

        // Higher z-score indicates more unusual time
        if (zScore > 3) {
          anomalyScore += 40; // Very unusual time
        } else if (zScore > 2) {
          anomalyScore += 25; // Unusual time
        } else if (zScore > 1.5) {
          anomalyScore += 10; // Somewhat unusual time
        }
      }

      // Check login day anomaly
      if (features['login_day_variance'] < 1) {
        // User typically logs in on consistent days
        const now = new Date();
        const currentDay = now.getDay();

        // Calculate typical login days
        const loginDays = loginHistory
          .filter(login => login.timestamp)
          .map(login => login.timestamp.getDay());

        // Check if current day is unusual
        const dayFrequency = loginDays.filter(day => day === currentDay).length / loginDays.length;
        if (dayFrequency < 0.1) {
          anomalyScore += 30; // Very unusual day
        } else if (dayFrequency < 0.2) {
          anomalyScore += 15; // Unusual day
        }
      }

      // Check login frequency anomaly
      if (features['login_frequency_daily'] > 3 * (features['login_frequency_weekly'] / 7)) {
        // Unusually high login frequency today
        anomalyScore += 20;
      }

      // Check login interval anomaly
      if (
        features['login_interval_mean'] > 0 &&
        features['login_interval_std'] > 0 &&
        features['inactive_period_before_login'] > 0
      ) {
        // Calculate z-score for current interval
        const zScore = Math.abs(
          (features['inactive_period_before_login'] - features['login_interval_mean']) /
            features['login_interval_std']
        );

        if (zScore > 3) {
          anomalyScore += 25; // Very unusual interval
        } else if (zScore > 2) {
          anomalyScore += 15; // Unusual interval
        }
      }

      // Check business hours vs. off-hours
      const now = new Date();
      const currentHour = now.getHours();
      const currentDay = now.getDay();
      const isBusinessHours =
        currentHour >= 9 && currentHour < 17 && currentDay >= 1 && currentDay <= 5;
      const isWeekend = currentDay === 0 || currentDay === 6;

      if (features['business_hours_login_ratio'] > 0.8 && !isBusinessHours) {
        // User typically logs in during business hours but this is outside
        anomalyScore += 20;
      }

      if (features['weekend_login_ratio'] < 0.2 && isWeekend) {
        // User rarely logs in on weekends but this is a weekend
        anomalyScore += 20;
      }

      // Cap the score at 100
      return Math.min(100, anomalyScore);
    } catch (error) {
      logger.error('Error detecting temporal anomalies', { error });
      return 0;
    }
  }

  /**
   * Detect location anomalies in authentication behavior
   * @param features Current authentication features
   * @param loginHistory User's login history
   * @returns Location anomaly score (0-100)
   */
  private async detectLocationAnomalies(
    features: Record<string, any>,
    loginHistory: any[]
  ): Promise<number> {
    try {
      if (loginHistory.length < 3) {
        return 0; // Not enough data for reliable detection
      }

      let anomalyScore = 0;

      // Check for new country/region/city
      if (features['is_new_country']) {
        anomalyScore += 50; // New country is highly suspicious
      } else if (features['is_new_region']) {
        anomalyScore += 30; // New region is suspicious
      } else if (features['is_new_city']) {
        anomalyScore += 15; // New city is somewhat suspicious
      }

      // Check for high-risk location
      if (features['high_risk_location']) {
        anomalyScore += 40;
      }

      // Check for VPN, proxy, or Tor
      if (features['vpn_detected']) {
        anomalyScore += 25;
      }

      if (features['proxy_detected']) {
        anomalyScore += 30;
      }

      if (features['tor_detected']) {
        anomalyScore += 50;
      }

      // Check for impossible travel
      if (features['max_travel_speed'] > 1000) {
        // Faster than commercial flight (1000 km/h)
        anomalyScore += 70;
      } else if (features['max_travel_speed'] > 500) {
        // Faster than high-speed train but slower than plane
        anomalyScore += 40;
      }

      // Check for unusual distance from last login
      if (features['distance_from_last_login'] > 1000) {
        // More than 1000 km from last login
        anomalyScore += 30;
      } else if (features['distance_from_last_login'] > 500) {
        // More than 500 km from last login
        anomalyScore += 15;
      }

      // Check for location diversity anomaly
      if (
        features['location_diversity'] === 1 &&
        (features['is_new_country'] || features['is_new_region'])
      ) {
        // User typically logs in from a single location but this is different
        anomalyScore += 35;
      }

      // Cap the score at 100
      return Math.min(100, anomalyScore);
    } catch (error) {
      logger.error('Error detecting location anomalies', { error });
      return 0;
    }
  }

  /**
   * Detect device anomalies in authentication behavior
   * @param features Current authentication features
   * @param loginHistory User's login history
   * @returns Device anomaly score (0-100)
   */
  private async detectDeviceAnomalies(
    features: Record<string, any>,
    loginHistory: any[]
  ): Promise<number> {
    try {
      if (loginHistory.length < 3) {
        return 0; // Not enough data for reliable detection
      }

      let anomalyScore = 0;

      // Check for new device
      if (features['is_new_device']) {
        anomalyScore += 40; // New device is suspicious
      }

      // Check for new browser or OS
      if (features['is_new_browser']) {
        anomalyScore += 20; // New browser is somewhat suspicious
      }

      if (features['is_new_os']) {
        anomalyScore += 25; // New OS is somewhat suspicious
      }

      // Check for suspicious device characteristics
      if (features['suspicious_device_characteristics']) {
        anomalyScore += 50;
      }

      // Check for multiple devices in a short period
      if (features['multiple_devices_short_period']) {
        anomalyScore += 35;
      }

      // Check for device diversity anomaly
      if (features['device_diversity'] === 1 && features['is_new_device']) {
        // User typically uses a single device but this is different
        anomalyScore += 40;
      }

      // Check for concurrent sessions from different devices
      if (features['concurrent_session_devices'] > 1 && features['is_new_device']) {
        anomalyScore += 30;
      }

      // Check for similar but not identical device (potential spoofing)
      if (features['session_with_similar_device']) {
        anomalyScore += 60;
      }

      // Cap the score at 100
      return Math.min(100, anomalyScore);
    } catch (error) {
      logger.error('Error detecting device anomalies', { error });
      return 0;
    }
  }

  /**
   * Detect behavior anomalies in authentication patterns
   * @param features Current authentication features
   * @param riskAssessments Previous risk assessments
   * @returns Behavior anomaly score (0-100)
   */
  private async detectBehaviorAnomalies(
    features: Record<string, any>,
    riskAssessments: any[]
  ): Promise<number> {
    try {
      if (riskAssessments.length < 5) {
        return 0; // Not enough data for reliable detection
      }

      let anomalyScore = 0;

      // Check for unusual failed login ratio
      if (features['failed_login_ratio'] > 0.3) {
        anomalyScore += 30; // High failed login ratio is suspicious
      }

      // Check for recent password reset
      if (features['password_reset_frequency'] > 2 && features['password_age'] < 3) {
        anomalyScore += 25; // Multiple recent password resets are suspicious
      }

      // Check for unusual MFA challenge frequency
      if (features['mfa_challenge_frequency'] > 5) {
        anomalyScore += 20; // Many MFA challenges may indicate brute force attempts
      }

      // Check for suspicious actions
      if (features['suspicious_action_frequency'] > 0) {
        anomalyScore += 40; // Previous suspicious actions increase risk
      }

      // Check for unusual session duration
      if (
        features['session_duration_mean'] > 0 &&
        features['session_duration_std'] > 0 &&
        features['session_age_mean'] > 0
      ) {
        // Calculate z-score for current session age
        const zScore = Math.abs(
          (features['session_age_mean'] - features['session_duration_mean']) /
            features['session_duration_std']
        );

        if (zScore > 3) {
          anomalyScore += 25; // Very unusual session duration
        } else if (zScore > 2) {
          anomalyScore += 15; // Unusual session duration
        }
      }

      // Check for overlapping sessions
      if (features['has_overlapping_session']) {
        anomalyScore += 45; // Overlapping sessions are highly suspicious
      }

      // Check for unusual action diversity
      if (features['action_diversity'] < 3 && features['action_entropy'] < 0.5) {
        // Limited action diversity may indicate automated behavior
        anomalyScore += 20;
      }

      // Check for unusual inactive period before login
      if (features['inactive_period_before_login'] > 30 * 24) {
        // More than 30 days of inactivity
        anomalyScore += 35;
      } else if (features['inactive_period_before_login'] > 14 * 24) {
        // More than 14 days of inactivity
        anomalyScore += 20;
      }

      // Cap the score at 100
      return Math.min(100, anomalyScore);
    } catch (error) {
      logger.error('Error detecting behavior anomalies', { error });
      return 0;
    }
  }

  /**
   * Calculate overall anomaly score from individual scores
   * @param anomalyScores Individual anomaly scores
   * @returns Overall anomaly score (0-100)
   */
  private calculateOverallAnomalyScore(anomalyScores: Record<string, number>): number {
    try {
      // Weighted average of individual scores
      const weights = {
        temporal_anomaly: 0.2,
        location_anomaly: 0.3,
        device_anomaly: 0.25,
        behavior_anomaly: 0.25,
      };

      let weightedScore = 0;
      let totalWeight = 0;

      for (const [key, weight] of Object.entries(weights)) {
        if (anomalyScores[key] !== undefined) {
          weightedScore += anomalyScores[key] * weight;
          totalWeight += weight;
        }
      }

      // Calculate final score
      const finalScore = totalWeight > 0 ? weightedScore / totalWeight : 0;

      // Round to nearest integer and ensure it's within 0-100 range
      return Math.min(100, Math.max(0, Math.round(finalScore)));
    } catch (error) {
      logger.error('Error calculating overall anomaly score', { error });
      return 0;
    }
  }

  /**
   * Generate detailed anomaly information
   * @param anomalyScores Anomaly scores
   * @param features Authentication features
   * @returns Detailed anomaly information
   */
  private generateAnomalyDetails(
    anomalyScores: Record<string, number>,
    features: Record<string, any>
  ): Record<string, any> {
    const details: Record<string, any> = {};

    try {
      // Temporal anomalies
      if (anomalyScores['temporal_anomaly'] && anomalyScores['temporal_anomaly'] > 30) {
        details['temporal'] = {
          score: anomalyScores['temporal_anomaly'],
          unusual_time:
            features['login_time_variance'] !== undefined && features['login_time_variance'] < 2,
          unusual_day:
            features['login_day_variance'] !== undefined && features['login_day_variance'] < 1,
          high_frequency:
            features['login_frequency_daily'] !== undefined &&
            features['login_frequency_weekly'] !== undefined &&
            features['login_frequency_daily'] > 3 * (features['login_frequency_weekly'] / 7),
          unusual_interval:
            features['inactive_period_before_login'] !== undefined &&
            features['login_interval_mean'] !== undefined &&
            features['login_interval_std'] !== undefined &&
            features['inactive_period_before_login'] >
              features['login_interval_mean'] + 2 * features['login_interval_std'],
        };
      }

      // Location anomalies
      if (anomalyScores['location_anomaly'] && anomalyScores['location_anomaly'] > 30) {
        details['location'] = {
          score: anomalyScores['location_anomaly'],
          new_country: Boolean(features['is_new_country']),
          new_region: Boolean(features['is_new_region']),
          new_city: Boolean(features['is_new_city']),
          high_risk_location: Boolean(features['high_risk_location']),
          vpn_detected: Boolean(features['vpn_detected']),
          proxy_detected: Boolean(features['proxy_detected']),
          tor_detected: Boolean(features['tor_detected']),
          impossible_travel:
            features['max_travel_speed'] !== undefined && features['max_travel_speed'] > 1000,
          unusual_distance:
            features['distance_from_last_login'] !== undefined &&
            features['distance_from_last_login'] > 500,
        };
      }

      // Device anomalies
      if (anomalyScores['device_anomaly'] && anomalyScores['device_anomaly'] > 30) {
        details['device'] = {
          score: anomalyScores['device_anomaly'],
          new_device: Boolean(features['is_new_device']),
          new_browser: Boolean(features['is_new_browser']),
          new_os: Boolean(features['is_new_os']),
          suspicious_characteristics: Boolean(features['suspicious_device_characteristics']),
          multiple_devices: Boolean(features['multiple_devices_short_period']),
          similar_device: Boolean(features['session_with_similar_device']),
        };
      }

      // Behavior anomalies
      if (anomalyScores['behavior_anomaly'] && anomalyScores['behavior_anomaly'] > 30) {
        details['behavior'] = {
          score: anomalyScores['behavior_anomaly'],
          high_failed_logins:
            features['failed_login_ratio'] !== undefined && features['failed_login_ratio'] > 0.3,
          recent_password_reset:
            features['password_reset_frequency'] !== undefined &&
            features['password_age'] !== undefined &&
            features['password_reset_frequency'] > 2 &&
            features['password_age'] < 3,
          high_mfa_challenges:
            features['mfa_challenge_frequency'] !== undefined &&
            features['mfa_challenge_frequency'] > 5,
          suspicious_actions:
            features['suspicious_action_frequency'] !== undefined &&
            features['suspicious_action_frequency'] > 0,
          unusual_session:
            features['session_age_mean'] !== undefined &&
            features['session_duration_mean'] !== undefined &&
            features['session_duration_std'] !== undefined &&
            features['session_age_mean'] >
              features['session_duration_mean'] + 2 * features['session_duration_std'],
          overlapping_sessions: Boolean(features['has_overlapping_session']),
          long_inactivity:
            features['inactive_period_before_login'] !== undefined &&
            features['inactive_period_before_login'] > 14 * 24,
        };
      }

      return details;
    } catch (error) {
      logger.error('Error generating anomaly details', { error });
      return {};
    }
  }

  /**
   * Calculate the mean of an array of numbers
   * @param values Array of numbers
   * @returns Mean value
   */
  private calculateMean(values: number[]): number {
    if (values.length === 0) return 0;
    return values.reduce((sum, value) => sum + value, 0) / values.length;
  }

  /**
   * Calculate the standard deviation of an array of numbers
   * @param values Array of numbers
   * @returns Standard deviation
   */
  private calculateStandardDeviation(values: number[]): number {
    if (values.length === 0) return 0;
    const mean = this.calculateMean(values);
    const variance =
      values.reduce((sum, value) => sum + Math.pow(value - mean, 2), 0) / values.length;
    return Math.sqrt(variance);
  }

  /**
   * Sanitize context for logging (remove sensitive data)
   * @param context Authentication context
   * @returns Sanitized context
   */
  private sanitizeContext(context: Record<string, any>): Record<string, any> {
    const sanitized = { ...context };

    // Remove sensitive fields
    delete sanitized['password'];
    delete sanitized['token'];
    delete sanitized['accessToken'];
    delete sanitized['refreshToken'];

    // Truncate potentially large fields
    if (sanitized['deviceFingerprint']) {
      sanitized['deviceFingerprint'] = 'present';
    }

    return sanitized;
  }
}
