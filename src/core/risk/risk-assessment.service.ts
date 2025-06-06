import { Injectable } from '@tsed/di';
import { riskConfig } from '../../config/risk.config';
import type { RiskAssessmentRepository } from '../../data/repositories/risk-assessment.repository';
import type { SessionRepository } from '../../data/repositories/session.repository';
import type { EventEmitter } from '../../infrastructure/events/event-emitter';
import { logger } from '../../infrastructure/logging/logger';
import type { AuditLogService } from '../audit/audit-log.service';
import type { DeviceFingerprintService } from './factors/device-fingerprint.service';
import type { GeolocationService } from './factors/geolocation.service';
import type { IpReputationService } from './factors/ip-reputation.service';
import type { ThreatIntelligenceService } from './factors/threat-intelligence.service';
import type { TimePatternService } from './factors/time-pattern.service';
import type { UserBehaviorService } from './factors/user-behavior.service';
import type { MachineLearningService } from './ml/machine-learning.service';
import { RiskEvent } from './risk-events';
import { RiskFactor, RiskLevel, type RiskAssessmentResult } from './risk-types';

@Injectable()
export class RiskAssessmentService {
  constructor(
    private ipReputationService: IpReputationService,
    private geolocationService: GeolocationService,
    private deviceFingerprintService: DeviceFingerprintService,
    private userBehaviorService: UserBehaviorService,
    private timePatternService: TimePatternService,
    private threatIntelligenceService: ThreatIntelligenceService,
    private machineLearningService: MachineLearningService,
    private riskAssessmentRepository: RiskAssessmentRepository,
    private sessionRepository: SessionRepository,
    private auditLogService: AuditLogService,
    private eventEmitter: EventEmitter
  ) {}

  /**
   * Assess risk for a login attempt
   * @param userId User ID (optional, for existing users)
   * @param context Authentication context
   * @returns Risk assessment result
   */
  async assessLoginRisk(
    userId: string | null,
    context: Record<string, any>
  ): Promise<RiskAssessmentResult> {
    try {
      const startTime = Date.now();
      logger.debug('Starting login risk assessment', {
        userId,
        context: this.sanitizeContext(context),
      });

      // Initialize risk factors
      const riskFactors: Record<RiskFactor, number> = {
        [RiskFactor.IP_REPUTATION]: 0,
        [RiskFactor.GEOLOCATION]: 0,
        [RiskFactor.DEVICE_FINGERPRINT]: 0,
        [RiskFactor.USER_BEHAVIOR]: 0,
        [RiskFactor.TIME_PATTERN]: 0,
        [RiskFactor.THREAT_INTELLIGENCE]: 0,
        [RiskFactor.MACHINE_LEARNING]: 0,
      };

      // Collect risk data from various services
      const promises: Promise<void>[] = [];

      // IP Reputation
      if (riskConfig.ipReputation.enabled && context['ipAddress']) {
        promises.push(
          this.ipReputationService.assessRisk(context['ipAddress'] as string).then(score => {
            riskFactors[RiskFactor.IP_REPUTATION] = score;
          })
        );
      }

      // Geolocation
      if (riskConfig.geolocation.enabled && context['ipAddress']) {
        promises.push(
          this.geolocationService.assessRisk(userId, context['ipAddress'] as string).then(score => {
            riskFactors[RiskFactor.GEOLOCATION] = score;
          })
        );
      }

      // Device Fingerprint
      if (riskConfig.deviceFingerprint.enabled && context['deviceFingerprint']) {
        promises.push(
          this.deviceFingerprintService
            .assessRisk(userId, context['deviceFingerprint'] as Record<string, any>)
            .then(score => {
              riskFactors[RiskFactor.DEVICE_FINGERPRINT] = score;
            })
        );
      }

      // User Behavior (only for existing users)
      if (riskConfig.userBehavior.enabled && userId) {
        promises.push(
          this.userBehaviorService.assessRisk(userId, context).then(score => {
            riskFactors[RiskFactor.USER_BEHAVIOR] = score;
          })
        );
      }

      // Time Pattern
      if (riskConfig.timePattern.enabled) {
        promises.push(
          this.timePatternService.assessRisk(userId, context).then(score => {
            riskFactors[RiskFactor.TIME_PATTERN] = score;
          })
        );
      }

      // Threat Intelligence
      if (riskConfig.threatIntelligence.enabled) {
        promises.push(
          this.threatIntelligenceService.assessRisk(userId, context).then(score => {
            riskFactors[RiskFactor.THREAT_INTELLIGENCE] = score;
          })
        );
      }

      // Machine Learning (only if enabled and for existing users)
      if (riskConfig.machineLearning.enabled && userId) {
        promises.push(
          this.machineLearningService.predictRisk(userId, context).then(score => {
            riskFactors[RiskFactor.MACHINE_LEARNING] = score;
          })
        );
      }

      // Wait for all risk assessments to complete
      await Promise.all(promises);

      // Calculate overall risk score
      const riskScore = this.calculateRiskScore(riskFactors);

      // Determine risk level
      const riskLevel = this.determineRiskLevel(riskScore);

      // Determine required actions
      const actions = this.determineRequiredActions(riskLevel);

      // Create risk assessment record
      const assessmentId = await this.saveRiskAssessment(
        userId,
        context,
        riskScore,
        riskLevel,
        riskFactors,
        undefined,
        undefined
      );

      // Log the assessment
      await this.auditLogService.create({
        userId,
        action: 'RISK_ASSESSMENT_COMPLETED',
        entityType: 'RISK_ASSESSMENT',
        entityId: assessmentId,
        metadata: {
          riskScore,
          riskLevel,
          riskFactors,
          actions,
          assessmentTime: Date.now() - startTime,
        },
      });

      // Emit risk assessment event
      this.eventEmitter.emit(RiskEvent.ASSESSMENT_COMPLETED, {
        userId,
        assessmentId,
        riskScore,
        riskLevel,
        riskFactors,
        actions,
        context: this.sanitizeContext(context),
        timestamp: new Date(),
      });

      logger.info('Login risk assessment completed', {
        userId,
        assessmentId,
        riskScore,
        riskLevel,
        assessmentTime: Date.now() - startTime,
      });

      return {
        id: assessmentId,
        userId,
        riskScore,
        riskLevel,
        riskFactors,
        actions,
        timestamp: new Date(),
      };
    } catch (error) {
      logger.error('Error during login risk assessment', { error, userId });

      // Return a default low-risk assessment in case of error
      return {
        id: 'error',
        userId,
        riskScore: riskConfig.scoring.defaultScore,
        riskLevel: RiskLevel.LOW,
        riskFactors: {
          [RiskFactor.IP_REPUTATION]: 0,
          [RiskFactor.GEOLOCATION]: 0,
          [RiskFactor.DEVICE_FINGERPRINT]: 0,
          [RiskFactor.USER_BEHAVIOR]: 0,
          [RiskFactor.TIME_PATTERN]: 0,
          [RiskFactor.THREAT_INTELLIGENCE]: 0,
          [RiskFactor.MACHINE_LEARNING]: 0,
        },
        actions: {
          requireMfa: false,
          allowRememberDevice: true,
          sessionDuration: riskConfig.adaptiveAuth.riskLevels.low.sessionDuration,
          allowedActions: ['all'],
          requireAdditionalVerification: false,
        },
        timestamp: new Date(),
      };
    }
  }

  /**
   * Assess risk for an ongoing session (continuous authentication)
   * @param sessionId Session ID
   * @param context Current context
   * @returns Risk assessment result
   */
  async assessSessionRisk(
    sessionId: string,
    context: Record<string, any>
  ): Promise<RiskAssessmentResult> {
    try {
      // Get session
      const session = await this.sessionRepository.findById(sessionId);
      if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
      }

      // Get previous risk assessment
      const previousAssessment =
        await this.riskAssessmentRepository.findLatestBySessionId(sessionId);

      // Get user ID from session
      const userId = session.userId;

      // Perform risk assessment
      const assessment = await this.assessLoginRisk(userId, {
        ...context,
        sessionId,
        isContinuousAuth: true,
        previousRiskScore: previousAssessment?.riskScore,
      });

      // Apply risk decay if appropriate
      if (
        previousAssessment &&
        previousAssessment.riskScore !== undefined &&
        assessment.riskScore < previousAssessment.riskScore
      ) {
        // Apply risk decay - don't let risk drop too quickly
        const decayedScore = Math.max(
          assessment.riskScore,
          previousAssessment.riskScore * (1 - riskConfig.continuousAuth.riskDecayRate)
        );
        assessment.riskScore = decayedScore;
        assessment.riskLevel = this.determineRiskLevel(decayedScore);
        assessment.actions = this.determineRequiredActions(assessment.riskLevel);
      } else if (
        previousAssessment &&
        previousAssessment.riskScore !== undefined &&
        assessment.riskScore > previousAssessment.riskScore
      ) {
        // Limit how quickly risk can increase
        const maxIncrease = riskConfig.continuousAuth.maxRiskIncrement;
        const cappedScore = Math.min(
          assessment.riskScore,
          previousAssessment.riskScore + maxIncrease
        );
        assessment.riskScore = cappedScore;
        assessment.riskLevel = this.determineRiskLevel(cappedScore);
        assessment.actions = this.determineRequiredActions(assessment.riskLevel);
      }

      // Update the assessment ID
      const assessmentId = await this.saveRiskAssessment(
        userId,
        context,
        assessment.riskScore,
        assessment.riskLevel,
        assessment.riskFactors,
        sessionId
      );
      assessment.id = assessmentId;

      // Emit continuous auth event
      this.eventEmitter.emit(RiskEvent.CONTINUOUS_ASSESSMENT_COMPLETED, {
        userId,
        sessionId,
        assessmentId,
        riskScore: assessment.riskScore,
        riskLevel: assessment.riskLevel,
        previousRiskScore: previousAssessment?.riskScore,
        previousRiskLevel: previousAssessment?.riskLevel,
        timestamp: new Date(),
      });

      return assessment;
    } catch (error) {
      logger.error('Error during session risk assessment', { error, sessionId });

      // Return a default medium-risk assessment in case of error
      return {
        id: 'error',
        userId: null,
        riskScore: 50,
        riskLevel: RiskLevel.MEDIUM,
        riskFactors: {
          [RiskFactor.IP_REPUTATION]: 0,
          [RiskFactor.GEOLOCATION]: 0,
          [RiskFactor.DEVICE_FINGERPRINT]: 0,
          [RiskFactor.USER_BEHAVIOR]: 0,
          [RiskFactor.TIME_PATTERN]: 0,
          [RiskFactor.THREAT_INTELLIGENCE]: 0,
          [RiskFactor.MACHINE_LEARNING]: 0,
        },
        actions: {
          requireMfa: true,
          allowRememberDevice: true,
          sessionDuration: riskConfig.adaptiveAuth.riskLevels.medium.sessionDuration,
          allowedActions: ['all'],
          requireAdditionalVerification: false,
        },
        timestamp: new Date(),
      };
    }
  }

  /**
   * Assess risk for a specific action
   * @param userId User ID
   * @param sessionId Session ID
   * @param action Action being performed
   * @param context Current context
   * @returns Risk assessment result
   */
  async assessActionRisk(
    userId: string,
    sessionId: string,
    action: string,
    context: Record<string, any>
  ): Promise<RiskAssessmentResult> {
    try {
      logger.debug('Starting action risk assessment', { userId, sessionId, action });

      // Check if this is a sensitive action requiring step-up auth
      const isSensitiveAction =
        riskConfig.adaptiveAuth.stepUpAuth.enabled &&
        riskConfig.adaptiveAuth.stepUpAuth.sensitiveActions.includes(action);

      // Get the latest session risk assessment
      const latestAssessment = await this.riskAssessmentRepository.findLatestBySessionId(sessionId);

      // For sensitive actions, perform a new risk assessment
      if (isSensitiveAction) {
        // Perform risk assessment with action context
        const assessment = await this.assessLoginRisk(userId, {
          ...context,
          sessionId,
          action,
          isActionAssessment: true,
        });

        // For sensitive actions, increase the risk level by at least one level
        const currentRiskLevel = assessment.riskLevel;
        let newRiskLevel = currentRiskLevel;

        switch (currentRiskLevel) {
          case RiskLevel.LOW:
            newRiskLevel = RiskLevel.MEDIUM;
            break;
          case RiskLevel.MEDIUM:
            newRiskLevel = RiskLevel.HIGH;
            break;
          case RiskLevel.HIGH:
          case RiskLevel.CRITICAL:
            newRiskLevel = RiskLevel.CRITICAL;
            break;
        }

        assessment.riskLevel = newRiskLevel;
        assessment.actions = this.determineRequiredActions(newRiskLevel);

        // Save the assessment
        const assessmentId = await this.saveRiskAssessment(
          userId,
          context,
          assessment.riskScore,
          assessment.riskLevel,
          assessment.riskFactors,
          sessionId,
          action
        );
        assessment.id = assessmentId;

        // Emit action risk event
        this.eventEmitter.emit(RiskEvent.ACTION_ASSESSMENT_COMPLETED, {
          userId,
          sessionId,
          action,
          assessmentId,
          riskScore: assessment.riskScore,
          riskLevel: assessment.riskLevel,
          requiresStepUp: true,
          timestamp: new Date(),
        });

        return assessment;
      } else if (latestAssessment) {
        // For non-sensitive actions, use the latest session assessment
        // but check if the action is allowed at the current risk level
        const riskLevel = latestAssessment.riskLevel;
        const actions = this.determineRequiredActions(riskLevel);

        // Ensure riskScore is a number
        const riskScore = latestAssessment.riskScore || 0;

        // Save a record of this action assessment
        const assessmentId = await this.saveRiskAssessment(
          userId,
          context,
          riskScore,
          riskLevel,
          latestAssessment.riskFactors as any,
          sessionId,
          action
        );

        // Emit action risk event
        this.eventEmitter.emit(RiskEvent.ACTION_ASSESSMENT_COMPLETED, {
          userId,
          sessionId,
          action,
          assessmentId,
          riskScore,
          riskLevel,
          requiresStepUp: false,
          timestamp: new Date(),
        });

        return {
          id: assessmentId,
          userId,
          riskScore,
          riskLevel,
          riskFactors: latestAssessment.riskFactors as any,
          actions,
          timestamp: new Date(),
        };
      } else {
        // If no previous assessment exists, perform a new one
        return await this.assessLoginRisk(userId, {
          ...context,
          sessionId,
          action,
          isActionAssessment: true,
        });
      }
    } catch (error) {
      logger.error('Error during action risk assessment', { error, userId, sessionId, action });

      // Return a default medium-risk assessment in case of error
      return {
        id: 'error',
        userId,
        riskScore: 50,
        riskLevel: RiskLevel.MEDIUM,
        riskFactors: {
          [RiskFactor.IP_REPUTATION]: 0,
          [RiskFactor.GEOLOCATION]: 0,
          [RiskFactor.DEVICE_FINGERPRINT]: 0,
          [RiskFactor.USER_BEHAVIOR]: 0,
          [RiskFactor.TIME_PATTERN]: 0,
          [RiskFactor.THREAT_INTELLIGENCE]: 0,
          [RiskFactor.MACHINE_LEARNING]: 0,
        },
        actions: {
          requireMfa: true,
          allowRememberDevice: true,
          sessionDuration: riskConfig.adaptiveAuth.riskLevels.medium.sessionDuration,
          allowedActions: ['all'],
          requireAdditionalVerification: false,
        },
        timestamp: new Date(),
      };
    }
  }

  /**
   * Calculate overall risk score based on individual risk factors
   * @param riskFactors Risk factors with scores
   * @returns Overall risk score (0-100)
   */
  private calculateRiskScore(riskFactors: Record<RiskFactor, number>): number {
    const weights = riskConfig.scoring.weights;

    let weightedScore = 0;
    let totalWeight = 0;

    // Calculate weighted score
    if (riskConfig.ipReputation.enabled) {
      weightedScore += riskFactors[RiskFactor.IP_REPUTATION] * weights.ipReputation;
      totalWeight += weights.ipReputation;
    }

    if (riskConfig.geolocation.enabled) {
      weightedScore += riskFactors[RiskFactor.GEOLOCATION] * weights.geolocation;
      totalWeight += weights.geolocation;
    }

    if (riskConfig.deviceFingerprint.enabled) {
      weightedScore += riskFactors[RiskFactor.DEVICE_FINGERPRINT] * weights.deviceFingerprint;
      totalWeight += weights.deviceFingerprint;
    }

    if (riskConfig.userBehavior.enabled) {
      weightedScore += riskFactors[RiskFactor.USER_BEHAVIOR] * weights.userBehavior;
      totalWeight += weights.userBehavior;
    }

    if (riskConfig.timePattern.enabled) {
      weightedScore += riskFactors[RiskFactor.TIME_PATTERN] * weights.timePattern;
      totalWeight += weights.timePattern;
    }

    if (riskConfig.threatIntelligence.enabled) {
      weightedScore += riskFactors[RiskFactor.THREAT_INTELLIGENCE] * weights.threatIntelligence;
      totalWeight += weights.threatIntelligence;
    }

    // If machine learning is enabled, give it special treatment
    if (riskConfig.machineLearning.enabled && riskFactors[RiskFactor.MACHINE_LEARNING] > 0) {
      // ML can override other factors if it detects a high-risk situation
      if (riskFactors[RiskFactor.MACHINE_LEARNING] > 75) {
        return Math.max(weightedScore / totalWeight, riskFactors[RiskFactor.MACHINE_LEARNING]);
      }

      // Otherwise, include it in the weighted average
      weightedScore += riskFactors[RiskFactor.MACHINE_LEARNING] * 0.3;
      totalWeight += 0.3;
    }

    // Calculate final score
    const finalScore =
      totalWeight > 0 ? weightedScore / totalWeight : riskConfig.scoring.defaultScore;

    // Round to nearest integer and ensure it's within 0-100 range
    return Math.min(100, Math.max(0, Math.round(finalScore)));
  }

  /**
   * Determine risk level based on risk score
   * @param riskScore Risk score (0-100)
   * @returns Risk level
   */
  private determineRiskLevel(riskScore: number): RiskLevel {
    const thresholds = riskConfig.scoring.thresholds;

    if (riskScore >= thresholds.high) {
      return riskScore >= 90 ? RiskLevel.CRITICAL : RiskLevel.HIGH;
    } else if (riskScore >= thresholds.medium) {
      return RiskLevel.MEDIUM;
    } else {
      return RiskLevel.LOW;
    }
  }

  /**
   * Determine required actions based on risk level
   * @param riskLevel Risk level
   * @returns Required actions
   */
  private determineRequiredActions(riskLevel: RiskLevel): Record<string, any> {
    const config = riskConfig.adaptiveAuth.riskLevels;

    switch (riskLevel) {
      case RiskLevel.CRITICAL:
        return {
          requireMfa: config.critical.requireMfa,
          allowRememberDevice: config.critical.allowRememberDevice,
          sessionDuration: config.critical.sessionDuration,
          allowedActions: config.critical.allowedActions,
          requireAdditionalVerification: config.critical.requireAdditionalVerification,
        };
      case RiskLevel.HIGH:
        return {
          requireMfa: config.high.requireMfa,
          allowRememberDevice: config.high.allowRememberDevice,
          sessionDuration: config.high.sessionDuration,
          allowedActions: config.high.allowedActions,
          requireAdditionalVerification: false,
        };
      case RiskLevel.MEDIUM:
        return {
          requireMfa: config.medium.requireMfa,
          allowRememberDevice: config.medium.allowRememberDevice,
          sessionDuration: config.medium.sessionDuration,
          allowedActions: config.medium.allowedActions,
          requireAdditionalVerification: false,
        };
      case RiskLevel.LOW:
      default:
        return {
          requireMfa: config.low.requireMfa,
          allowRememberDevice: config.low.allowRememberDevice,
          sessionDuration: config.low.sessionDuration,
          allowedActions: config.low.allowedActions,
          requireAdditionalVerification: false,
        };
    }
  }

  /**
   * Save risk assessment to database
   * @param userId User ID
   * @param context Authentication context
   * @param riskScore Risk score
   * @param riskLevel Risk level
   * @param riskFactors Risk factors
   * @param sessionId Session ID (optional)
   * @param action Action being assessed (optional)
   * @returns Assessment ID
   */
  private async saveRiskAssessment(
    userId: string | null,
    context: Record<string, any>,
    riskScore: number,
    riskLevel: RiskLevel,
    riskFactors: Record<RiskFactor, number>,
    sessionId?: string,
    action?: string
  ): Promise<string> {
    try {
      // Convert RiskLevel from lowercase to uppercase to match the model's enum
      const convertedRiskLevel = this.convertRiskLevel(riskLevel);

      // Convert risk factors to a format the repository can handle
      const convertedRiskFactors = this.convertRiskFactors(riskFactors);

      // Ensure riskScore is a number
      const safeRiskScore = Math.round(riskScore || 0);

      const assessment = await this.riskAssessmentRepository.create({
        userId,
        sessionId,
        ipAddress: context['ipAddress'] as string | undefined,
        userAgent: context['userAgent'] as string | undefined,
        deviceId: context['deviceFingerprint'] as string | undefined, // Map deviceFingerprint to deviceId
        riskScore: safeRiskScore,
        riskLevel: convertedRiskLevel,
        riskFactors: convertedRiskFactors,
        action: action,
      });

      return assessment.id;
    } catch (error) {
      logger.error('Failed to save risk assessment', { error, userId, sessionId });
      return 'error-saving';
    }
  }

  /**
   * Convert RiskLevel from risk-types.ts format to risk-assessment.model.ts format
   * Since we've standardized the enum values, this now simply returns the same value
   * @param riskLevel Risk level from risk-types.ts
   * @returns Risk level for risk-assessment.model.ts
   */
  private convertRiskLevel(riskLevel: RiskLevel): RiskLevel {
    // Now that we've standardized the enum values, we can just return the input
    return riskLevel;
  }

  /**
   * Convert risk factors to a format the repository can handle
   * @param riskFactors Risk factors from risk-types.ts
   * @returns Risk factors for the repository
   */
  private convertRiskFactors(riskFactors: Record<RiskFactor, number>): Record<string, any> {
    // Convert to a simple object with string keys
    const result: Record<string, any> = {};

    for (const [factor, score] of Object.entries(riskFactors)) {
      result[factor] = score;
    }

    return result;
  }

  /**
   * Sanitize context for logging (remove sensitive data)
   * @param context Authentication context
   * @returns Sanitized context
   */
  private sanitizeContext(context: Record<string, any>): Record<string, any> {
    const sanitized = { ...context };

    // Remove sensitive fields
    if (sanitized['password']) delete sanitized['password'];
    if (sanitized['token']) delete sanitized['token'];
    if (sanitized['accessToken']) delete sanitized['accessToken'];
    if (sanitized['refreshToken']) delete sanitized['refreshToken'];

    // Truncate potentially large fields
    if (sanitized['deviceFingerprint']) {
      sanitized['deviceFingerprint'] = 'present';
    }

    return sanitized;
  }
}
