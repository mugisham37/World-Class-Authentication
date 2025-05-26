import type {
  RiskAssessment,
  RiskAssessmentFilterOptions,
} from '../../data/models/risk-assessment.model';
import { RiskLevel } from '../../data/models/risk-assessment.model';
import { ActionType } from '../../data/models/action-type.enum';
import { riskAssessmentRepository } from '../../data/repositories/risk-assessment.repository';
import { logger } from '../../infrastructure/logging/logger';
import { emitEvent } from '../events/event-bus';
import { EventType } from '../events/event-types';
import { securityConfig } from '../../config/security-config';

/**
 * Risk assessment service for evaluating authentication risks
 */
export class RiskAssessmentService {
  /**
   * Assess login risk
   * @param userId User ID
   * @param ipAddress Client IP address
   * @param userAgent Client user agent
   * @returns Risk assessment result
   */
  async assessLoginRisk(
    userId: string,
    ipAddress: string,
    userAgent: string
  ): Promise<RiskAssessment> {
    try {
      // Calculate risk factors
      const riskFactors = await this.calculateRiskFactors(userId, ipAddress, userAgent);

      // Calculate overall risk score (0-100)
      const riskScore = this.calculateRiskScore(riskFactors);

      // Determine risk level
      const riskLevel = this.determineRiskLevel(riskScore);

      // Determine action based on risk level
      const action = this.determineAction(riskLevel);

      // Create risk assessment record
      const assessment = await riskAssessmentRepository.create({
        userId,
        ipAddress,
        userAgent,
        riskScore,
        riskLevel,
        riskFactors,
        action,
      });

      // Emit risk assessment completed event
      emitEvent(EventType.RISK_ASSESSMENT_COMPLETED, {
        userId,
        riskScore,
        riskLevel,
        factors: riskFactors,
        action,
        timestamp: new Date(),
      });

      logger.info('Login risk assessment completed', {
        userId,
        riskScore,
        riskLevel,
        action,
      });

      return assessment;
    } catch (error) {
      logger.error('Failed to assess login risk', {
        error,
        userId,
        ipAddress,
      });

      // Return a default low-risk assessment in case of error
      return await riskAssessmentRepository.create({
        userId,
        ipAddress,
        userAgent,
        riskScore: 0,
        riskLevel: RiskLevel.LOW,
        riskFactors: {},
        action: ActionType.ALLOW,
      });
    }
  }

  /**
   * Update session ID for a risk assessment
   * @param id Risk assessment ID
   * @param sessionId Session ID
   * @returns Updated risk assessment
   */
  async updateSessionId(id: string, sessionId: string): Promise<RiskAssessment> {
    try {
      const assessment = await riskAssessmentRepository.findById(id);
      if (!assessment) {
        logger.warn('Risk assessment not found for update', {
          id,
          sessionId,
        });
        return assessment as any;
      }

      // Update assessment with session ID
      return await riskAssessmentRepository.update(id, {
        sessionId,
      });
    } catch (error) {
      logger.error('Failed to update risk assessment session ID', {
        error,
        id,
        sessionId,
      });
      return null as any;
    }
  }

  /**
   * Calculate risk factors
   * @param userId User ID
   * @param ipAddress Client IP address
   * @param userAgent Client user agent
   * @returns Risk factors
   */
  private async calculateRiskFactors(
    userId: string,
    ipAddress: string,
    userAgent: string
  ): Promise<Record<string, number>> {
    // In a real implementation, this would include:
    // - IP geolocation analysis
    // - Device fingerprinting
    // - Behavioral analysis
    // - Time-based patterns
    // - Known compromised IP check
    // - Tor exit node check
    // - VPN detection
    // - etc.

    // For now, we'll use a simplified implementation
    const factors: Record<string, number> = {
      ipReputation: 0, // 0-100, higher is riskier
      deviceReputation: 0, // 0-100, higher is riskier
      locationAnomaly: 0, // 0-100, higher is riskier
      timeAnomaly: 0, // 0-100, higher is riskier
      behavioralAnomaly: 0, // 0-100, higher is riskier
    };

    // Check for previous logins from this IP
    const filterOptions: RiskAssessmentFilterOptions = { limit: 10 };
    const previousAssessments = await riskAssessmentRepository.findByIpAddress(
      ipAddress,
      filterOptions
    );
    const previousUserAssessments = await riskAssessmentRepository.findByUserId(
      userId,
      filterOptions
    );

    // Analyze IP reputation
    if (previousAssessments.length === 0) {
      // New IP address
      factors['ipReputation'] = 50;
    } else {
      // Known IP address
      factors['ipReputation'] = 10;
    }

    // Analyze location anomaly
    if (previousUserAssessments.some(a => a.ipAddress === ipAddress)) {
      // User has logged in from this IP before
      factors['locationAnomaly'] = 0;
    } else if (previousUserAssessments.length > 0) {
      // User has never logged in from this IP
      factors['locationAnomaly'] = 60;
    } else {
      // New user, no history
      factors['locationAnomaly'] = 30;
    }

    // Check time of day
    const hour = new Date().getHours();
    if (hour < 6 || hour > 22) {
      // Unusual login time
      factors['timeAnomaly'] = 40;
    } else {
      // Normal login time
      factors['timeAnomaly'] = 0;
    }

    // Simple user agent analysis
    if (userAgent.includes('bot') || userAgent.includes('crawler')) {
      factors['deviceReputation'] = 80;
    } else if (
      userAgent.includes('Mozilla') ||
      userAgent.includes('Chrome') ||
      userAgent.includes('Safari')
    ) {
      factors['deviceReputation'] = 10;
    } else {
      factors['deviceReputation'] = 30;
    }

    // For now, behavioral anomaly is random
    // In a real implementation, this would be based on user behavior patterns
    factors['behavioralAnomaly'] = Math.floor(Math.random() * 20);

    return factors;
  }

  /**
   * Calculate overall risk score
   * @param factors Risk factors
   * @returns Risk score (0-100)
   */
  private calculateRiskScore(factors: Record<string, number>): number {
    // Weights for each factor
    const weights: Record<string, number> = {
      ipReputation: 0.3,
      deviceReputation: 0.2,
      locationAnomaly: 0.2,
      timeAnomaly: 0.15,
      behavioralAnomaly: 0.15,
    };

    // Calculate weighted score
    let score = 0;
    let totalWeight = 0;

    for (const [factor, value] of Object.entries(factors)) {
      const weight = weights[factor] || 0;
      score += value * weight;
      totalWeight += weight;
    }

    // Normalize score
    if (totalWeight > 0) {
      score = score / totalWeight;
    }

    // Round to nearest integer
    return Math.round(score);
  }

  /**
   * Determine risk level based on score
   * @param score Risk score
   * @returns Risk level
   */
  private determineRiskLevel(score: number): RiskLevel {
    const thresholds = securityConfig.risk?.thresholds || {
      low: 25,
      medium: 50,
      high: 75,
    };

    if (score < thresholds.low) {
      return RiskLevel.LOW;
    } else if (score < thresholds.medium) {
      return RiskLevel.MEDIUM;
    } else if (score < thresholds.high) {
      return RiskLevel.HIGH;
    } else {
      return RiskLevel.CRITICAL;
    }
  }

  /**
   * Determine action based on risk level
   * @param riskLevel Risk level
   * @returns Action to take
   */
  private determineAction(riskLevel: RiskLevel): ActionType {
    // Convert enum values to lowercase strings for compatibility with config
    const riskLevelKey = riskLevel.toString().toLowerCase();

    // Default actions if not configured
    const defaultActions = {
      low: ActionType.ALLOW,
      medium: ActionType.ALLOW,
      high: ActionType.CHALLENGE,
      critical: ActionType.BLOCK,
    };

    const actions = securityConfig.risk?.actions || defaultActions;

    // Map the string-based config to ActionType enum
    switch (riskLevelKey) {
      case 'low':
        return this.convertToActionType(actions.low);
      case 'medium':
        return this.convertToActionType(actions.medium);
      case 'high':
        return this.convertToActionType(actions.high);
      case 'critical':
        return this.convertToActionType(actions.critical);
      default:
        return ActionType.ALLOW; // Fallback
    }
  }

  /**
   * Convert string to RiskLevel enum
   * @param level Risk level string
   * @returns RiskLevel enum value
   */

  /**
   * Convert string to ActionType enum
   * @param action Action type string
   * @returns ActionType enum value
   */
  private convertToActionType(action: string): ActionType {
    return ActionType[action.toUpperCase() as keyof typeof ActionType];
  }
}

// Export a singleton instance
export const riskAssessmentService = new RiskAssessmentService();
