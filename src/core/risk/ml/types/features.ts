/**
 * Feature interfaces for machine learning risk assessment
 * These interfaces define the structure of features extracted for ML models
 */

/**
 * Temporal features related to login timing patterns
 */
export interface TemporalFeatures {
  login_frequency_daily: number;
  login_frequency_weekly: number;
  login_time_variance: number;
  login_day_variance: number;
  login_interval_mean: number;
  login_interval_std: number;
  weekend_login_ratio: number;
  business_hours_login_ratio: number;
}

/**
 * Location features related to geographic patterns
 */
export interface LocationFeatures {
  location_diversity: number;
  location_entropy: number;
  is_new_country: boolean;
  is_new_region: boolean;
  is_new_city: boolean;
  distance_from_last_login: number;
  max_travel_speed: number;
  high_risk_location: boolean;
  vpn_detected: boolean;
  proxy_detected: boolean;
  tor_detected: boolean;
}

/**
 * Device features related to hardware and software used
 */
export interface DeviceFeatures {
  device_diversity: number;
  is_new_device: boolean;
  is_new_browser: boolean;
  is_new_os: boolean;
  device_age: number;
  device_usage_frequency: number;
  device_entropy: number;
  multiple_devices_short_period: boolean;
  suspicious_device_characteristics: boolean;
}

/**
 * Behavior features related to user actions and patterns
 */
export interface BehaviorFeatures {
  action_diversity: number;
  action_entropy: number;
  failed_login_ratio: number;
  password_reset_frequency: number;
  mfa_challenge_frequency: number;
  suspicious_action_frequency: number;
  session_duration_mean: number;
  session_duration_std: number;
  pages_per_session_mean: number;
  inactive_period_before_login: number;
}

/**
 * Session features related to user sessions
 */
export interface SessionFeatures {
  active_session_count: number;
  concurrent_session_locations: number;
  concurrent_session_devices: number;
  session_location_entropy: number;
  session_device_entropy: number;
  session_with_similar_ip: boolean;
  session_with_similar_device: boolean;
  session_age_mean: number;
  has_overlapping_session: boolean;
}

/**
 * User account features related to the user profile
 */
export interface UserFeatures {
  account_age: number;
  has_mfa: boolean;
  mfa_method_count: number;
  password_age: number;
  password_strength: number;
  email_verified: boolean;
  phone_verified: boolean;
  is_admin: boolean;
  has_recovery_methods: boolean;
  recovery_method_count: number;
  login_count: number;
}

/**
 * Combined features for ML risk assessment
 */
export interface RiskAssessmentFeatures
  extends Partial<TemporalFeatures>,
    Partial<LocationFeatures>,
    Partial<DeviceFeatures>,
    Partial<BehaviorFeatures>,
    Partial<SessionFeatures>,
    Partial<UserFeatures> {
  timestamp: number;
  error?: boolean;
}
