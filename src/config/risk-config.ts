import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define risk assessment config schema with Zod
const riskConfigSchema = z.object({
  // Scoring configuration
  scoring: z.object({
    defaultScore: z.number().min(0).max(100).default(0),
    thresholds: z.object({
      low: z.number().min(0).max(100).default(25),
      medium: z.number().min(0).max(100).default(50),
      high: z.number().min(0).max(100).default(75),
      suspicious: z.number().min(0).max(100).default(50),
      malicious: z.number().min(0).max(100).default(75),
      critical: z.number().min(0).max(100).default(90),
    }),
    weights: z.object({
      ipReputation: z.number().min(0).max(1).default(0.2),
      geolocation: z.number().min(0).max(1).default(0.15),
      deviceFingerprint: z.number().min(0).max(1).default(0.15),
      userBehavior: z.number().min(0).max(1).default(0.2),
      timePattern: z.number().min(0).max(1).default(0.1),
      threatIntelligence: z.number().min(0).max(1).default(0.2),
    }),
  }),

  // IP reputation risk assessment configuration
  ipReputation: z.object({
    enabled: z.boolean().default(true),
    providers: z
      .array(z.enum(['abuseipdb', 'ipqualityscore', 'ipinfo', 'local']))
      .default(['local']),
    cacheTime: z
      .number()
      .int()
      .positive()
      .default(24 * 60 * 60), // 24 hours
    thresholds: z.object({
      suspicious: z.number().min(0).max(100).default(50),
      malicious: z.number().min(0).max(100).default(75),
      low: z.number().min(0).max(100).default(20),
      high: z.number().min(0).max(100).default(75),
    }),
  }),

  // Geolocation risk assessment configuration
  geolocation: z.object({
    enabled: z.boolean().default(true),
    providers: z.array(z.enum(['ipinfo', 'maxmind', 'ipgeolocation', 'local'])).default(['local']),
    cacheTime: z
      .number()
      .int()
      .positive()
      .default(7 * 24 * 60 * 60), // 7 days
    riskFactors: z.object({
      countryChange: z.number().min(0).max(100).default(70),
      impossibleTravel: z.number().min(0).max(100).default(90),
      highRiskCountry: z.number().min(0).max(100).default(60),
      vpnDetected: z.number().min(0).max(100).default(40),
      torDetected: z.number().min(0).max(100).default(80),
      proxyDetected: z.number().min(0).max(100).default(50),
    }),
    highRiskCountries: z.array(z.string()).default(['KP', 'IR', 'SY', 'SD', 'CU']),
  }),

  // Device fingerprint risk assessment configuration
  deviceFingerprint: z.object({
    enabled: z.boolean().default(true),
    components: z
      .array(
        z.enum([
          'userAgent',
          'language',
          'colorDepth',
          'deviceMemory',
          'hardwareConcurrency',
          'screenResolution',
          'timezoneOffset',
          'timezone',
          'sessionStorage',
          'localStorage',
          'indexedDb',
          'plugins',
          'fonts',
          'canvas',
          'webgl',
          'webglVendor',
          'adBlock',
          'hasLiedLanguages',
          'hasLiedResolution',
          'hasLiedOs',
          'hasLiedBrowser',
          'touchSupport',
          'audio',
          'availableScreenResolution',
          'cpuClass',
          'platform',
          'webglVendorAndRenderer',
          'openDatabase',
          'addBehavior',
        ])
      )
      .default([
        'userAgent',
        'language',
        'colorDepth',
        'screenResolution',
        'timezoneOffset',
        'sessionStorage',
        'localStorage',
        'indexedDb',
        'plugins',
      ]),
    riskFactors: z.object({
      newDevice: z.number().min(0).max(100).default(50),
      suspiciousDevice: z.number().min(0).max(100).default(70),
      multipleAccounts: z.number().min(0).max(100).default(60),
      deviceSpoofing: z.number().min(0).max(100).default(80),
    }),
    trustDeviceDuration: z
      .number()
      .int()
      .positive()
      .default(30 * 24 * 60 * 60), // 30 days
  }),

  // User behavior risk assessment configuration
  userBehavior: z.object({
    enabled: z.boolean().default(true),
    analysisWindow: z
      .number()
      .int()
      .positive()
      .default(30 * 24 * 60 * 60), // 30 days
    minDataPoints: z.number().int().positive().default(5),
    riskFactors: z.object({
      unusualLoginTime: z.number().min(0).max(100).default(40),
      unusualLoginLocation: z.number().min(0).max(100).default(60),
      unusualLoginFrequency: z.number().min(0).max(100).default(50),
      unusualActivityPattern: z.number().min(0).max(100).default(70),
      rapidAccountSwitching: z.number().min(0).max(100).default(80),
    }),
  }),

  // Time pattern risk assessment configuration
  timePattern: z.object({
    enabled: z.boolean().default(true),
    timeWindowHours: z.number().int().positive().default(3),
    windowHours: z.number().int().positive().default(720), // 30 days
    riskFactors: z.object({
      offHoursLogin: z.number().min(0).max(100).default(40),
      irregularPattern: z.number().min(0).max(100).default(60),
      highFrequencyLogin: z.number().min(0).max(100).default(50),
      accountSwitching: z.number().min(0).max(100).default(70),
    }),
  }),

  // Threat intelligence risk assessment configuration
  threatIntelligence: z.object({
    enabled: z.boolean().default(true),
    providers: z
      .array(z.enum(['haveibeenpwned', 'virustotal', 'abuseipdb', 'local']))
      .default(['local']),
    cacheTime: z
      .number()
      .int()
      .positive()
      .default(24 * 60 * 60), // 24 hours
    riskFactors: z.object({
      knownThreatActor: z.number().min(0).max(100).default(90),
      compromisedCredentials: z.number().min(0).max(100).default(80),
      malwareDetected: z.number().min(0).max(100).default(85),
      botnetActivity: z.number().min(0).max(100).default(90),
      phishingAttempt: z.number().min(0).max(100).default(85),
      attackPattern: z.number().min(0).max(100).default(70),
    }),
  }),

  // Adaptive authentication configuration
  adaptiveAuth: z.object({
    enabled: z.boolean().default(true),
    riskLevels: z.object({
      low: z.object({
        requireMfa: z.boolean().default(false),
        allowRememberDevice: z.boolean().default(true),
        sessionDuration: z
          .number()
          .int()
          .positive()
          .default(24 * 60 * 60), // 24 hours
        allowedActions: z.array(z.string()).default(['all']),
      }),
      medium: z.object({
        requireMfa: z.boolean().default(true),
        allowRememberDevice: z.boolean().default(true),
        sessionDuration: z
          .number()
          .int()
          .positive()
          .default(12 * 60 * 60), // 12 hours
        allowedActions: z.array(z.string()).default(['all']),
      }),
      high: z.object({
        requireMfa: z.boolean().default(true),
        allowRememberDevice: z.boolean().default(false),
        sessionDuration: z
          .number()
          .int()
          .positive()
          .default(1 * 60 * 60), // 1 hour
        allowedActions: z.array(z.string()).default(['read', 'view', 'basic', 'standard']),
      }),
      critical: z.object({
        requireMfa: z.boolean().default(true),
        allowRememberDevice: z.boolean().default(false),
        sessionDuration: z
          .number()
          .int()
          .positive()
          .default(15 * 60), // 15 minutes
        allowedActions: z.array(z.string()).default(['read', 'view', 'basic']),
        requireAdditionalVerification: z.boolean().default(true),
      }),
    }),
    stepUpAuth: z.object({
      enabled: z.boolean().default(true),
      sensitiveActions: z
        .array(z.string())
        .default([
          'payment',
          'transfer',
          'profile.update',
          'security.update',
          'admin',
          'updateProfile',
          'changePassword',
          'changeEmail',
          'changePhone',
          'addPaymentMethod',
          'makePayment',
          'transferFunds',
          'deleteAccount',
          'addRecoveryMethod',
          'disableMfa',
        ]),
      timeWindow: z
        .number()
        .int()
        .positive()
        .default(15 * 60), // 15 minutes
    }),
  }),

  // Continuous authentication configuration
  continuousAuth: z.object({
    enabled: z.boolean().default(true),
    monitoringInterval: z
      .number()
      .int()
      .positive()
      .default(5 * 60), // 5 minutes
    assessmentInterval: z
      .number()
      .int()
      .positive()
      .default(5 * 60), // 5 minutes
    maxRiskIncrement: z.number().min(0).max(100).default(20),
    riskDecayRate: z.number().min(0).max(1).default(0.05),
    riskFactors: z.object({
      inactivityThreshold: z
        .number()
        .int()
        .positive()
        .default(30 * 60), // 30 minutes
      suspiciousActivityThreshold: z.number().min(0).max(100).default(70),
      locationChangeThreshold: z.number().int().positive().default(50), // km
    }),
    triggerEvents: z
      .array(z.string())
      .default(['pageNavigation', 'sensitiveAction', 'idleTimeout', 'ipChange', 'deviceChange']),
  }),

  // Machine learning risk assessment configuration
  machineLearning: z.object({
    enabled: z.boolean().default(true),
    modelUpdateInterval: z
      .number()
      .int()
      .positive()
      .default(7 * 24 * 60 * 60), // 7 days
    minTrainingData: z.number().int().positive().default(100),
    anomalyThreshold: z.number().min(0).max(1).default(0.95),
    featureImportance: z.object({
      loginTime: z.number().min(0).max(1).default(0.15),
      loginLocation: z.number().min(0).max(1).default(0.2),
      deviceType: z.number().min(0).max(1).default(0.15),
      ipAddress: z.number().min(0).max(1).default(0.2),
      userAgent: z.number().min(0).max(1).default(0.1),
      interactionPattern: z.number().min(0).max(1).default(0.2),
    }),
    minDataPoints: z.number().int().positive().default(10),
  }),

  // Risk rules configuration
  rules: z.object({
    enabled: z.boolean().default(true),
    evaluationOrder: z.array(z.string()).default(['whitelist', 'blacklist', 'custom']),
    defaultAction: z.string().default('allow'),
  }),

  // Risk event handling configuration
  events: z.object({
    notifyUser: z.object({
      enabled: z.boolean().default(true),
      events: z
        .array(z.string())
        .default([
          'risk.high.detected',
          'risk.critical.detected',
          'risk.location.change.detected',
          'risk.device.change.detected',
          'risk.compromised.credentials.detected',
        ]),
    }),
    notifyAdmin: z.object({
      enabled: z.boolean().default(true),
      events: z
        .array(z.string())
        .default([
          'risk.critical.detected',
          'risk.threat.detected',
          'risk.impossible.travel.detected',
          'risk.botnet.activity.detected',
        ]),
    }),
  }),
});

// Parse and validate environment variables
const rawConfig = {
  // Scoring configuration
  scoring: {
    defaultScore: env.getNumber('RISK_DEFAULT_SCORE', 0),
    thresholds: {
      low: env.getNumber('RISK_THRESHOLD_LOW', 25),
      medium: env.getNumber('RISK_THRESHOLD_MEDIUM', 50),
      high: env.getNumber('RISK_THRESHOLD_HIGH', 75),
      suspicious: env.getNumber('RISK_THRESHOLD_SUSPICIOUS', 50),
      malicious: env.getNumber('RISK_THRESHOLD_MALICIOUS', 75),
      critical: env.getNumber('RISK_THRESHOLD_CRITICAL', 90),
    },
    weights: {
      ipReputation: env.getNumber('RISK_WEIGHT_IP_REPUTATION', 0.2),
      geolocation: env.getNumber('RISK_WEIGHT_GEOLOCATION', 0.15),
      deviceFingerprint: env.getNumber('RISK_WEIGHT_DEVICE_FINGERPRINT', 0.15),
      userBehavior: env.getNumber('RISK_WEIGHT_USER_BEHAVIOR', 0.2),
      timePattern: env.getNumber('RISK_WEIGHT_TIME_PATTERN', 0.1),
      threatIntelligence: env.getNumber('RISK_WEIGHT_THREAT_INTELLIGENCE', 0.2),
    },
  },

  // IP reputation risk assessment configuration
  ipReputation: {
    enabled: env.getBoolean('RISK_IP_REPUTATION_ENABLED', true),
    providers: (env.get('RISK_IP_REPUTATION_PROVIDERS')?.split(',') as any) || ['local'],
    cacheTime: env.getNumber('RISK_IP_REPUTATION_CACHE_TIME', 24 * 60 * 60),
    thresholds: {
      suspicious: env.getNumber('RISK_IP_REPUTATION_THRESHOLD_SUSPICIOUS', 50),
      malicious: env.getNumber('RISK_IP_REPUTATION_THRESHOLD_MALICIOUS', 75),
      low: env.getNumber('RISK_IP_REPUTATION_THRESHOLD_LOW', 20),
      high: env.getNumber('RISK_IP_REPUTATION_THRESHOLD_HIGH', 75),
    },
  },

  // Geolocation risk assessment configuration
  geolocation: {
    enabled: env.getBoolean('RISK_GEOLOCATION_ENABLED', true),
    providers: (env.get('RISK_GEOLOCATION_PROVIDERS')?.split(',') as any) || ['local'],
    cacheTime: env.getNumber('RISK_GEOLOCATION_CACHE_TIME', 7 * 24 * 60 * 60),
    riskFactors: {
      countryChange: env.getNumber('RISK_GEOLOCATION_FACTOR_COUNTRY_CHANGE', 70),
      impossibleTravel: env.getNumber('RISK_GEOLOCATION_FACTOR_IMPOSSIBLE_TRAVEL', 90),
      highRiskCountry: env.getNumber('RISK_GEOLOCATION_FACTOR_HIGH_RISK_COUNTRY', 60),
      vpnDetected: env.getNumber('RISK_GEOLOCATION_FACTOR_VPN_DETECTED', 40),
      torDetected: env.getNumber('RISK_GEOLOCATION_FACTOR_TOR_DETECTED', 80),
      proxyDetected: env.getNumber('RISK_GEOLOCATION_FACTOR_PROXY_DETECTED', 50),
    },
    highRiskCountries: env.get('RISK_GEOLOCATION_HIGH_RISK_COUNTRIES')?.split(',') || [
      'KP',
      'IR',
      'SY',
      'SD',
      'CU',
    ],
  },

  // Device fingerprint risk assessment configuration
  deviceFingerprint: {
    enabled: env.getBoolean('RISK_DEVICE_FINGERPRINT_ENABLED', true),
    components: (env.get('RISK_DEVICE_FINGERPRINT_COMPONENTS')?.split(',') as any) || [
      'userAgent',
      'language',
      'colorDepth',
      'screenResolution',
      'timezoneOffset',
      'sessionStorage',
      'localStorage',
      'indexedDb',
      'plugins',
    ],
    riskFactors: {
      newDevice: env.getNumber('RISK_DEVICE_FINGERPRINT_FACTOR_NEW_DEVICE', 50),
      suspiciousDevice: env.getNumber('RISK_DEVICE_FINGERPRINT_FACTOR_SUSPICIOUS_DEVICE', 70),
      multipleAccounts: env.getNumber('RISK_DEVICE_FINGERPRINT_FACTOR_MULTIPLE_ACCOUNTS', 60),
      deviceSpoofing: env.getNumber('RISK_DEVICE_FINGERPRINT_FACTOR_DEVICE_SPOOFING', 80),
    },
    trustDeviceDuration: env.getNumber('RISK_DEVICE_FINGERPRINT_TRUST_DURATION', 30 * 24 * 60 * 60),
  },

  // User behavior risk assessment configuration
  userBehavior: {
    enabled: env.getBoolean('RISK_USER_BEHAVIOR_ENABLED', true),
    analysisWindow: env.getNumber('RISK_USER_BEHAVIOR_ANALYSIS_WINDOW', 30 * 24 * 60 * 60),
    minDataPoints: env.getNumber('RISK_USER_BEHAVIOR_MIN_DATA_POINTS', 5),
    riskFactors: {
      unusualLoginTime: env.getNumber('RISK_USER_BEHAVIOR_FACTOR_UNUSUAL_LOGIN_TIME', 40),
      unusualLoginLocation: env.getNumber('RISK_USER_BEHAVIOR_FACTOR_UNUSUAL_LOGIN_LOCATION', 60),
      unusualLoginFrequency: env.getNumber('RISK_USER_BEHAVIOR_FACTOR_UNUSUAL_LOGIN_FREQUENCY', 50),
      unusualActivityPattern: env.getNumber(
        'RISK_USER_BEHAVIOR_FACTOR_UNUSUAL_ACTIVITY_PATTERN',
        70
      ),
      rapidAccountSwitching: env.getNumber('RISK_USER_BEHAVIOR_FACTOR_RAPID_ACCOUNT_SWITCHING', 80),
    },
  },

  // Time pattern risk assessment configuration
  timePattern: {
    enabled: env.getBoolean('RISK_TIME_PATTERN_ENABLED', true),
    timeWindowHours: env.getNumber('RISK_TIME_PATTERN_WINDOW_HOURS', 3),
    windowHours: env.getNumber('RISK_TIME_PATTERN_WINDOW_HOURS', 720),
    riskFactors: {
      offHoursLogin: env.getNumber('RISK_TIME_PATTERN_FACTOR_OFF_HOURS_LOGIN', 40),
      irregularPattern: env.getNumber('RISK_TIME_PATTERN_FACTOR_IRREGULAR_PATTERN', 60),
      highFrequencyLogin: env.getNumber('RISK_TIME_PATTERN_FACTOR_HIGH_FREQUENCY_LOGIN', 50),
      accountSwitching: env.getNumber('RISK_TIME_PATTERN_FACTOR_ACCOUNT_SWITCHING', 70),
    },
  },

  // Threat intelligence risk assessment configuration
  threatIntelligence: {
    enabled: env.getBoolean('RISK_THREAT_INTELLIGENCE_ENABLED', true),
    providers: (env.get('RISK_THREAT_INTELLIGENCE_PROVIDERS')?.split(',') as any) || ['local'],
    cacheTime: env.getNumber('RISK_THREAT_INTELLIGENCE_CACHE_TIME', 24 * 60 * 60),
    riskFactors: {
      knownThreatActor: env.getNumber('RISK_THREAT_INTELLIGENCE_FACTOR_KNOWN_THREAT_ACTOR', 90),
      compromisedCredentials: env.getNumber(
        'RISK_THREAT_INTELLIGENCE_FACTOR_COMPROMISED_CREDENTIALS',
        80
      ),
      malwareDetected: env.getNumber('RISK_THREAT_INTELLIGENCE_FACTOR_MALWARE_DETECTED', 85),
      botnetActivity: env.getNumber('RISK_THREAT_INTELLIGENCE_FACTOR_BOTNET_ACTIVITY', 90),
      phishingAttempt: env.getNumber('RISK_THREAT_INTELLIGENCE_FACTOR_PHISHING_ATTEMPT', 85),
      attackPattern: env.getNumber('RISK_THREAT_INTELLIGENCE_FACTOR_ATTACK_PATTERN', 70),
    },
  },

  // Adaptive authentication configuration
  adaptiveAuth: {
    enabled: env.getBoolean('RISK_ADAPTIVE_AUTH_ENABLED', true),
    riskLevels: {
      low: {
        requireMfa: env.getBoolean('RISK_ADAPTIVE_AUTH_LOW_REQUIRE_MFA', false),
        allowRememberDevice: env.getBoolean('RISK_ADAPTIVE_AUTH_LOW_ALLOW_REMEMBER_DEVICE', true),
        sessionDuration: env.getNumber('RISK_ADAPTIVE_AUTH_LOW_SESSION_DURATION', 24 * 60 * 60),
        allowedActions: env.get('RISK_ADAPTIVE_AUTH_LOW_ALLOWED_ACTIONS')?.split(',') || ['all'],
      },
      medium: {
        requireMfa: env.getBoolean('RISK_ADAPTIVE_AUTH_MEDIUM_REQUIRE_MFA', true),
        allowRememberDevice: env.getBoolean(
          'RISK_ADAPTIVE_AUTH_MEDIUM_ALLOW_REMEMBER_DEVICE',
          true
        ),
        sessionDuration: env.getNumber('RISK_ADAPTIVE_AUTH_MEDIUM_SESSION_DURATION', 12 * 60 * 60),
        allowedActions: env.get('RISK_ADAPTIVE_AUTH_MEDIUM_ALLOWED_ACTIONS')?.split(',') || ['all'],
      },
      high: {
        requireMfa: env.getBoolean('RISK_ADAPTIVE_AUTH_HIGH_REQUIRE_MFA', true),
        allowRememberDevice: env.getBoolean('RISK_ADAPTIVE_AUTH_HIGH_ALLOW_REMEMBER_DEVICE', false),
        sessionDuration: env.getNumber('RISK_ADAPTIVE_AUTH_HIGH_SESSION_DURATION', 1 * 60 * 60),
        allowedActions: env.get('RISK_ADAPTIVE_AUTH_HIGH_ALLOWED_ACTIONS')?.split(',') || [
          'read',
          'view',
          'basic',
          'standard',
        ],
      },
      critical: {
        requireMfa: env.getBoolean('RISK_ADAPTIVE_AUTH_CRITICAL_REQUIRE_MFA', true),
        allowRememberDevice: env.getBoolean(
          'RISK_ADAPTIVE_AUTH_CRITICAL_ALLOW_REMEMBER_DEVICE',
          false
        ),
        sessionDuration: env.getNumber('RISK_ADAPTIVE_AUTH_CRITICAL_SESSION_DURATION', 15 * 60),
        allowedActions: env.get('RISK_ADAPTIVE_AUTH_CRITICAL_ALLOWED_ACTIONS')?.split(',') || [
          'read',
          'view',
          'basic',
        ],
        requireAdditionalVerification: env.getBoolean(
          'RISK_ADAPTIVE_AUTH_CRITICAL_REQUIRE_ADDITIONAL_VERIFICATION',
          true
        ),
      },
    },
    stepUpAuth: {
      enabled: env.getBoolean('RISK_STEP_UP_AUTH_ENABLED', true),
      sensitiveActions: env.get('RISK_STEP_UP_AUTH_SENSITIVE_ACTIONS')?.split(',') || [
        'payment',
        'transfer',
        'profile.update',
        'security.update',
        'admin',
        'updateProfile',
        'changePassword',
        'changeEmail',
        'changePhone',
        'addPaymentMethod',
        'makePayment',
        'transferFunds',
        'deleteAccount',
        'addRecoveryMethod',
        'disableMfa',
      ],
      timeWindow: env.getNumber('RISK_STEP_UP_AUTH_TIME_WINDOW', 15 * 60),
    },
  },

  // Continuous authentication configuration
  continuousAuth: {
    enabled: env.getBoolean('RISK_CONTINUOUS_AUTH_ENABLED', true),
    monitoringInterval: env.getNumber('RISK_CONTINUOUS_AUTH_MONITORING_INTERVAL', 5 * 60),
    assessmentInterval: env.getNumber('RISK_CONTINUOUS_AUTH_ASSESSMENT_INTERVAL', 5 * 60),
    maxRiskIncrement: env.getNumber('RISK_CONTINUOUS_AUTH_MAX_RISK_INCREMENT', 20),
    riskDecayRate: env.getNumber('RISK_CONTINUOUS_AUTH_RISK_DECAY_RATE', 0.05),
    riskFactors: {
      inactivityThreshold: env.getNumber('RISK_CONTINUOUS_AUTH_INACTIVITY_THRESHOLD', 30 * 60),
      suspiciousActivityThreshold: env.getNumber(
        'RISK_CONTINUOUS_AUTH_SUSPICIOUS_ACTIVITY_THRESHOLD',
        70
      ),
      locationChangeThreshold: env.getNumber('RISK_CONTINUOUS_AUTH_LOCATION_CHANGE_THRESHOLD', 50),
    },
    triggerEvents: env.get('RISK_CONTINUOUS_AUTH_TRIGGER_EVENTS')?.split(',') || [
      'pageNavigation',
      'sensitiveAction',
      'idleTimeout',
      'ipChange',
      'deviceChange',
    ],
  },

  // Machine learning risk assessment configuration
  machineLearning: {
    enabled: env.getBoolean('RISK_ML_ENABLED', true),
    modelUpdateInterval: env.getNumber('RISK_ML_MODEL_UPDATE_INTERVAL', 7 * 24 * 60 * 60),
    minTrainingData: env.getNumber('RISK_ML_MIN_TRAINING_DATA', 100),
    anomalyThreshold: env.getNumber('RISK_ML_ANOMALY_THRESHOLD', 0.95),
    featureImportance: {
      loginTime: env.getNumber('RISK_ML_FEATURE_IMPORTANCE_LOGIN_TIME', 0.15),
      loginLocation: env.getNumber('RISK_ML_FEATURE_IMPORTANCE_LOGIN_LOCATION', 0.2),
      deviceType: env.getNumber('RISK_ML_FEATURE_IMPORTANCE_DEVICE_TYPE', 0.15),
      ipAddress: env.getNumber('RISK_ML_FEATURE_IMPORTANCE_IP_ADDRESS', 0.2),
      userAgent: env.getNumber('RISK_ML_FEATURE_IMPORTANCE_USER_AGENT', 0.1),
      interactionPattern: env.getNumber('RISK_ML_FEATURE_IMPORTANCE_INTERACTION_PATTERN', 0.2),
    },
    minDataPoints: env.getNumber('RISK_ML_MIN_DATA_POINTS', 10),
  },

  // Risk rules configuration
  rules: {
    enabled: env.getBoolean('RISK_RULES_ENABLED', true),
    evaluationOrder: env.get('RISK_RULES_EVALUATION_ORDER')?.split(',') || [
      'whitelist',
      'blacklist',
      'custom',
    ],
    defaultAction: env.get('RISK_RULES_DEFAULT_ACTION', 'allow'),
  },

  // Risk event handling configuration
  events: {
    notifyUser: {
      enabled: env.getBoolean('RISK_EVENTS_NOTIFY_USER_ENABLED', true),
      events: env.get('RISK_EVENTS_NOTIFY_USER_EVENTS')?.split(',') || [
        'risk.high.detected',
        'risk.critical.detected',
        'risk.location.change.detected',
        'risk.device.change.detected',
        'risk.compromised.credentials.detected',
      ],
    },
    notifyAdmin: {
      enabled: env.getBoolean('RISK_EVENTS_NOTIFY_ADMIN_ENABLED', true),
      events: env.get('RISK_EVENTS_NOTIFY_ADMIN_EVENTS')?.split(',') || [
        'risk.critical.detected',
        'risk.threat.detected',
        'risk.impossible.travel.detected',
        'risk.botnet.activity.detected',
      ],
    },
  },
};

// Validate and export config
export const riskConfig = validateConfig(riskConfigSchema, rawConfig);

// Export config type
export type RiskConfig = typeof riskConfig;
