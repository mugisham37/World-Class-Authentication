/**
 * Interfaces for machine learning risk assessment results
 */

/**
 * Anomaly detection results interface
 */
export interface AnomalyResults {
  anomalyScores: {
    overall_anomaly: number;
    temporal_anomaly?: number;
    location_anomaly?: number;
    device_anomaly?: number;
    behavior_anomaly?: number;
    [key: string]: number | undefined;
  };
  anomalyDetails?: Record<string, any>;
}

/**
 * Behavioral clustering results interface
 */
export interface ClusterResults {
  clusterId: string;
  clusterName?: string;
  similarity: number;
  confidence?: number;
  anomalyScore?: number;
  alternativeClusters?: Array<{
    clusterId: string;
    clusterName?: string;
    confidence?: number;
  }>;
}

/**
 * Risk assessment features interface
 */
export interface RiskFeatures {
  // Network features
  vpn_detected: boolean;
  proxy_detected: boolean;
  tor_detected: boolean;

  // Location features
  is_new_country: boolean;

  // Device features
  is_new_device: boolean;
  suspicious_device_characteristics: boolean;

  // Travel features
  impossible_travel: boolean;

  // User security features
  has_mfa: boolean;
  mfa_method_count: number;

  // Device history features
  device_age: number;
  device_usage_frequency: number;

  // Account features
  account_age: number;
  login_count: number;

  // Allow additional properties
  [key: string]: any;
}

/**
 * ML prediction event data interface
 */
export interface MLPredictionEvent {
  userId: string;
  riskScore: number;
  anomalyScores: AnomalyResults['anomalyScores'];
  clusterInfo: {
    clusterId: string;
    similarity: number;
  };
  timestamp: Date;
}
