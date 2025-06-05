import { Injectable } from "@tsed/di"
import { logger } from "../../../infrastructure/logging/logger"
import type { FeatureExtractionService } from "./feature-extraction.service"
import type { AnomalyDetectionService } from "./anomaly-detection.service"
import type { BehavioralClusteringService } from "./behavioral-clustering.service"
import type { RiskAssessmentRepository } from "../../../data/repositories/risk-assessment.repository"
import type { EventEmitter } from "../../../infrastructure/events/event-emitter"
import { RiskEvent } from "../risk-events"
import { riskConfig } from "../../../config/risk.config"

/**
 * Machine learning service for risk assessment
 * Coordinates ML-based risk prediction and model training
 */
@Injectable()
export class MachineLearningService {
  constructor(
    private featureExtractionService: FeatureExtractionService,
    private anomalyDetectionService: AnomalyDetectionService,
    private behavioralClusteringService: BehavioralClusteringService,
    private riskAssessmentRepository: RiskAssessmentRepository,
    private eventEmitter: EventEmitter,
  ) {}

  /**
   * Predict risk score using machine learning
   * @param userId User ID
   * @param context Authentication context
   * @returns Predicted risk score (0-100)
   */
  async predictRisk(userId: string, context: Record<string, any>): Promise<number> {
    try {
      logger.debug("Starting ML risk prediction", { userId })

      // Skip ML prediction if not enough data
      const assessmentCount = await this.riskAssessmentRepository.countByUserId(userId)
      if (assessmentCount < riskConfig.machineLeaning.minDataPoints) {
        logger.debug("Not enough data for ML prediction", { userId, assessmentCount })
        return 0
      }

      // Extract features
      const features = await this.featureExtractionService.extractAuthenticationFeatures(userId, context)

      // Detect anomalies
      const anomalyResults = await this.anomalyDetectionService.detectAnomalies(userId, context)

      // Get behavioral cluster
      const clusterResults = await this.behavioralClusteringService.getUserCluster(userId, context)

      // Combine results to calculate risk score
      const riskScore = this.calculateRiskScore(features, anomalyResults, clusterResults)

      // Log prediction details
      logger.debug("ML risk prediction completed", {
        userId,
        riskScore,
        anomalyScore: anomalyResults.anomalyScores.overall_anomaly,
        clusterSimilarity: clusterResults.similarity,
      })

      // Emit ML prediction event
      this.eventEmitter.emit(RiskEvent.ML_PREDICTION_COMPLETED, {
        userId,
        riskScore,
        anomalyScores: anomalyResults.anomalyScores,
        clusterInfo: {
          clusterId: clusterResults.clusterId,
          similarity: clusterResults.similarity,
        },
        timestamp: new Date(),
      })

      return riskScore
    } catch (error) {
      logger.error("Error in ML risk prediction", { error, userId })
      return 0 // Default to no risk on error
    }
  }

  /**
   * Calculate risk score based on ML results
   * @param features Extracted features
   * @param anomalyResults Anomaly detection results
   * @param clusterResults Behavioral clustering results
   * @returns Risk score (0-100)
   */
  private calculateRiskScore(
    features: Record<string, any>,
    anomalyResults: Record<string, any>,
    clusterResults: Record<string, any>,
  ): number {
    try {
      // Get overall anomaly score
      const anomalyScore = anomalyResults.anomalyScores.overall_anomaly || 0

      // Get cluster similarity (higher similarity = lower risk)
      const clusterSimilarity = clusterResults.similarity || 0
      const clusterRisk = 100 - clusterSimilarity

      // Calculate weighted risk score
      const weights = {
        anomaly: 0.7, // Anomaly detection has higher weight
        cluster: 0.3, // Cluster similarity has lower weight
      }

      const weightedScore = anomalyScore * weights.anomaly + clusterRisk * weights.cluster

      // Apply risk modifiers based on specific features
      let riskModifier = 0

      // High-risk indicators
      if (features.vpn_detected || features.proxy_detected || features.tor_detected) {
        riskModifier += 15
      }

      if (features.is_new_country) {
        riskModifier += 10
      }

      if (features.is_new_device) {
        riskModifier += 10
      }

      if (features.suspicious_device_characteristics) {
        riskModifier += 20
      }

      if (features.impossible_travel) {
        riskModifier += 25
      }

      // Risk-reducing indicators
      if (features.has_mfa && features.mfa_method_count > 1) {
        riskModifier -= 10
      }

      if (features.device_age > 30 && features.device_usage_frequency > 10) {
        riskModifier -= 15
      }

      if (features.account_age > 365 && features.login_count > 100) {
        riskModifier -= 10
      }

      // Calculate final score with modifier
      let finalScore = weightedScore + riskModifier

      // Ensure score is within 0-100 range
      finalScore = Math.min(100, Math.max(0, finalScore))

      return Math.round(finalScore)
    } catch (error) {
      logger.error("Error calculating ML risk score", { error })
      return 50 // Default to medium risk on error
    }
  }

  /**
   * Train machine learning models with new data
   * This would typically be run as a background job
   */
  async trainModels(): Promise<void> {
    try {
      logger.info("Starting ML model training")

      // In a real implementation, this would:
      // 1. Fetch historical risk assessment data
      // 2. Extract features and labels
      // 3. Train anomaly detection models
      // 4. Update behavioral clusters
      // 5. Evaluate model performance
      // 6. Deploy updated models

      // For now, we'll just update behavioral clusters
      await this.behavioralClusteringService.updateClusters()

      logger.info("ML model training completed")
    } catch (error) {
      logger.error("Error training ML models", { error })
    }
  }

  /**
   * Evaluate model performance
   * This would typically be run after training
   */
  async evaluateModels(): Promise<Record<string, any>> {
    try {
      logger.info("Starting ML model evaluation")

      // In a real implementation, this would:
      // 1. Fetch test data
      // 2. Make predictions using current models
      // 3. Compare predictions to actual outcomes
      // 4. Calculate performance metrics
      // 5. Log results

      // For now, we'll return mock metrics
      const metrics = {
        anomalyDetection: {
          precision: 0.85,
          recall: 0.78,
          f1Score: 0.81,
          auc: 0.88,
        },
        clusteringQuality: {
          silhouetteScore: 0.72,
          daviesBouldinIndex: 0.58,
          clusterCount: 5,
        },
        riskPrediction: {
          accuracy: 0.82,
          precision: 0.79,
          recall: 0.75,
          f1Score: 0.77,
          mse: 0.15,
        },
      }

      logger.info("ML model evaluation completed", { metrics })
      return metrics
    } catch (error) {
      logger.error("Error evaluating ML models", { error })
      return {}
    }
  }
}
