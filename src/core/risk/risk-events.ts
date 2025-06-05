/**
 * Risk event types
 */
export enum RiskEvent {
  ASSESSMENT_COMPLETED = 'risk.assessment.completed',
  CONTINUOUS_ASSESSMENT_COMPLETED = 'risk.assessment.continuous.completed',
  ACTION_ASSESSMENT_COMPLETED = 'risk.assessment.action.completed',
  HIGH_RISK_DETECTED = 'risk.high.detected',
  CRITICAL_RISK_DETECTED = 'risk.critical.detected',
  ANOMALY_DETECTED = 'risk.anomaly.detected',
  RULE_TRIGGERED = 'risk.rule.triggered',
  THREAT_DETECTED = 'risk.threat.detected',
  LOCATION_CHANGE_DETECTED = 'risk.location.change.detected',
  IMPOSSIBLE_TRAVEL_DETECTED = 'risk.impossible.travel.detected',
  DEVICE_CHANGE_DETECTED = 'risk.device.change.detected',
  BEHAVIOR_CHANGE_DETECTED = 'risk.behavior.change.detected',
  COMPROMISED_CREDENTIALS_DETECTED = 'risk.compromised.credentials.detected',
  BOTNET_ACTIVITY_DETECTED = 'risk.botnet.activity.detected',
  PHISHING_ATTEMPT_DETECTED = 'risk.phishing.attempt.detected',
  ATTACK_PATTERN_DETECTED = 'risk.attack.pattern.detected',
  OFF_HOURS_LOGIN_DETECTED = 'risk.off.hours.login.detected',
  IRREGULAR_PATTERN_DETECTED = 'risk.irregular.pattern.detected',
  HIGH_FREQUENCY_LOGIN_DETECTED = 'risk.high.frequency.login.detected',
  ACCOUNT_SWITCHING_DETECTED = 'risk.account.switching.detected',
  ML_PREDICTION_COMPLETED = 'risk.ml.prediction.completed',
  THREAT_ACTOR_DETECTED = 'risk.threat.actor.detected',
}

/**
 * Risk event payload interface
 */
export interface RiskEventPayload {
  userId?: string | null;
  sessionId?: string;
  assessmentId?: string;
  riskScore?: number;
  riskLevel?: string;
  riskFactors?: Record<string, number>;
  actions?: Record<string, any>;
  context?: Record<string, any>;
  timestamp: Date;
  [key: string]: any;
}
