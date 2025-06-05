import { Injectable } from '@tsed/di';
import { logger } from '../../../infrastructure/logging/logger';
import type { FeatureExtractionService } from './feature-extraction.service';
import type { UserLoginHistoryRepository } from '../../../data/repositories/user-login-history.repository';
import type { UserRepository } from '../../../data/repositories/user.repository';
import type { CacheService } from '../../cache/cache.service';

/**
 * Behavioral clustering service for risk assessment
 * Clusters users based on behavior patterns for anomaly detection
 */
@Injectable()
export class BehavioralClusteringService {
  private readonly CACHE_PREFIX = 'behavioral-cluster:';
  private readonly CACHE_TTL = 24 * 60 * 60; // 24 hours

  constructor(
    private featureExtractionService: FeatureExtractionService,
    private userLoginHistoryRepository: UserLoginHistoryRepository,
    private userRepository: UserRepository,
    private cacheService: CacheService
  ) {}

  /**
   * Get behavioral cluster for a user
   * @param userId User ID
   * @param context Authentication context
   * @returns Cluster information and similarity score
   */
  async getUserCluster(userId: string, context: Record<string, any>): Promise<Record<string, any>> {
    try {
      logger.debug('Getting behavioral cluster for user', { userId });

      // Check cache first
      const cacheKey = `${this.CACHE_PREFIX}${userId}`;
      const cachedCluster = await this.cacheService.get<Record<string, any>>(cacheKey);

      if (cachedCluster) {
        logger.debug('Using cached behavioral cluster', {
          userId,
          clusterId: cachedCluster['clusterId'],
        });
        return this.evaluateClusterSimilarity(cachedCluster, context);
      }

      // Extract features for the user
      const features = await this.featureExtractionService.extractAuthenticationFeatures(
        userId,
        context
      );

      // Get user's login history
      const loginHistory = await this.userLoginHistoryRepository.findRecentByUserId(userId, 50);

      // Determine user's behavioral cluster
      const cluster = await this.determineCluster(features, loginHistory);

      // Cache the cluster information
      await this.cacheService.set(cacheKey, cluster, this.CACHE_TTL);

      // Evaluate similarity between current behavior and cluster
      return this.evaluateClusterSimilarity(cluster, context);
    } catch (error) {
      logger.error('Error getting behavioral cluster for user', { error, userId });
      return {
        clusterId: 'unknown',
        clusterName: 'Unknown',
        similarity: 0,
        confidence: 0,
        anomalyScore: 50,
      };
    }
  }

  /**
   * Determine behavioral cluster for a user based on features
   * @param features User's behavioral features
   * @param loginHistory User's login history
   * @returns Cluster information
   */
  private async determineCluster(
    features: Record<string, any>,
    loginHistory: any[]
  ): Promise<Record<string, any>> {
    try {
      // In a real implementation, this would use a clustering algorithm
      // For now, we'll use a simple rule-based approach

      // Define cluster characteristics
      const clusters = [
        {
          id: 'regular-business',
          name: 'Regular Business Hours',
          characteristics: {
            business_hours_login_ratio: { min: 0.7, weight: 3 },
            weekend_login_ratio: { max: 0.3, weight: 2 },
            login_time_variance: { max: 3, weight: 2 },
            login_day_variance: { max: 2, weight: 1 },
            location_diversity: { max: 3, weight: 1 },
            device_diversity: { max: 2, weight: 1 },
          },
        },
        {
          id: 'mobile-worker',
          name: 'Mobile Worker',
          characteristics: {
            location_diversity: { min: 3, weight: 3 },
            device_diversity: { min: 2, weight: 2 },
            login_time_variance: { min: 3, weight: 2 },
            login_day_variance: { min: 2, weight: 1 },
            business_hours_login_ratio: { max: 0.7, weight: 1 },
          },
        },
        {
          id: 'night-worker',
          name: 'Night Shift Worker',
          characteristics: {
            business_hours_login_ratio: { max: 0.3, weight: 3 },
            login_time_variance: { max: 3, weight: 2 },
            login_day_variance: { max: 2, weight: 1 },
          },
        },
        {
          id: 'weekend-worker',
          name: 'Weekend Worker',
          characteristics: {
            weekend_login_ratio: { min: 0.5, weight: 3 },
            business_hours_login_ratio: { variable: true, weight: 1 },
          },
        },
        {
          id: 'irregular',
          name: 'Irregular Pattern',
          characteristics: {
            login_time_variance: { min: 5, weight: 3 },
            login_day_variance: { min: 3, weight: 2 },
            location_diversity: { variable: true, weight: 1 },
            device_diversity: { variable: true, weight: 1 },
          },
        },
      ];

      // Calculate match scores for each cluster
      const scores = clusters.map(cluster => {
        let score = 0;
        let maxPossibleScore = 0;

        for (const [feature, criteria] of Object.entries(cluster.characteristics)) {
          const value = features[feature];
          const weight = criteria.weight || 1;
          maxPossibleScore += weight * 10;

          if (value === undefined) continue;

          if (criteria.min !== undefined && criteria.max !== undefined) {
            // Value should be within range
            if (value >= criteria.min && value <= criteria.max) {
              score += weight * 10;
            } else if (value < criteria.min) {
              score += weight * ((10 * value) / criteria.min);
            } else if (value > criteria.max) {
              score += weight * ((10 * criteria.max) / value);
            }
          } else if (criteria.min !== undefined) {
            // Value should be at least min
            if (value >= criteria.min) {
              score += weight * 10;
            } else {
              score += weight * ((10 * value) / criteria.min);
            }
          } else if (criteria.max !== undefined) {
            // Value should be at most max
            if (value <= criteria.max) {
              score += weight * 10;
            } else {
              score += weight * ((10 * criteria.max) / value);
            }
          } else if (criteria.variable !== undefined) {
            // No specific criteria, just check if value exists
            score += weight * 5;
          }
        }

        return {
          clusterId: cluster.id,
          clusterName: cluster.name,
          score,
          confidence: maxPossibleScore > 0 ? (score / maxPossibleScore) * 100 : 0,
        };
      });

      // Sort by score and get the best match
      scores.sort((a, b) => b.score - a.score);
      const bestMatch = scores[0] || {
        clusterId: 'unknown',
        clusterName: 'Unknown',
        confidence: 0,
      };

      return {
        clusterId: bestMatch.clusterId,
        clusterName: bestMatch.clusterName,
        confidence: bestMatch.confidence,
        alternativeClusters: scores.slice(1, 3).map(s => ({
          clusterId: s.clusterId,
          clusterName: s.clusterName,
          confidence: s.confidence,
        })),
      };
    } catch (error) {
      logger.error('Error determining behavioral cluster', { error });
      return {
        clusterId: 'unknown',
        clusterName: 'Unknown',
        confidence: 0,
        alternativeClusters: [],
      };
    }
  }

  /**
   * Evaluate similarity between current behavior and cluster
   * @param cluster User's behavioral cluster
   * @param context Current authentication context
   * @returns Similarity evaluation
   */
  private evaluateClusterSimilarity(
    cluster: Record<string, any>,
    context: Record<string, any>
  ): Record<string, any> {
    try {
      // In a real implementation, this would compare current behavior to cluster centroid
      // For now, we'll use a simple time-based approach for demonstration

      let similarity = 100; // Start with perfect similarity
      let anomalyScore = 0;

      // Check time-based similarity for time-sensitive clusters
      if (
        cluster['clusterId'] === 'regular-business' ||
        cluster['clusterId'] === 'night-worker' ||
        cluster['clusterId'] === 'weekend-worker'
      ) {
        const now = new Date();
        const currentHour = now.getHours();
        const currentDay = now.getDay();
        const isWeekend = currentDay === 0 || currentDay === 6;
        const isBusinessHours = currentHour >= 9 && currentHour < 17;

        if (cluster['clusterId'] === 'regular-business') {
          // Regular business users typically log in during business hours on weekdays
          if (isWeekend) {
            similarity -= 40;
            anomalyScore += 40;
          } else if (!isBusinessHours) {
            similarity -= 30;
            anomalyScore += 30;
          }
        } else if (cluster['clusterId'] === 'night-worker') {
          // Night workers typically log in during night hours
          if (currentHour >= 9 && currentHour < 20) {
            similarity -= 40;
            anomalyScore += 40;
          }
        } else if (cluster['clusterId'] === 'weekend-worker') {
          // Weekend workers typically log in during weekends
          if (!isWeekend) {
            similarity -= 40;
            anomalyScore += 40;
          }
        }
      }

      // Check location-based similarity
      if (context['countryCode'] && context['isNewCountry']) {
        similarity -= 30;
        anomalyScore += 30;
      }

      // Check device-based similarity
      if (context['deviceFingerprint'] && context['isNewDevice']) {
        similarity -= 30;
        anomalyScore += 30;
      }

      // Adjust based on cluster confidence
      if (cluster['confidence'] < 70) {
        // Lower confidence means less reliable similarity assessment
        similarity = Math.max(similarity - (70 - cluster['confidence']) / 2, 0);
      }

      return {
        ...cluster,
        similarity: Math.max(0, similarity),
        anomalyScore: Math.min(100, anomalyScore),
      };
    } catch (error) {
      logger.error('Error evaluating cluster similarity', { error });
      return {
        ...cluster,
        similarity: 0,
        anomalyScore: 50,
      };
    }
  }

  /**
   * Update behavioral clusters based on new data
   * This would typically be run as a background job
   */
  async updateClusters(): Promise<void> {
    try {
      logger.info('Starting behavioral cluster update');

      // In a real implementation, this would:
      // 1. Fetch recent login data for all users
      // 2. Extract features for each user
      // 3. Run clustering algorithm (e.g., k-means, DBSCAN)
      // 4. Update cluster definitions
      // 5. Update user-cluster assignments

      // For now, we'll just log that it would happen
      logger.info('Behavioral cluster update completed');
    } catch (error) {
      logger.error('Error updating behavioral clusters', { error });
    }
  }
}
