import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define risk assessment config schema with Zod
const riskConfigSchema = z.object({
  scoring: z.object({
    defaultScore: z.number().min(0).max(100).default(0),
    thresholds: z.object({
      low: z.number().min(0).max(100).default(25),
      medium: z.number().min(0).max(100).default(50),
      high: z.number().min(0).max(100).default(75),
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
    }),
  }),
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
    highRiskCountries: z.array(z.string()).default([]),
  }),
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
  timePattern: z.object({
    enabled: z.boolean().default(true),
    timeWindowHours: z.number().int().positive().default(3),
    riskFactors: z.object({
      offHoursLogin: z.number().min(0).max(100).default(40),
      irregularPattern: z.number().min(0).max(100).default(60),
      highFrequencyLogin: z.number().min(0).max(100).default(50),
      accountSwitching: z.number().min(0).max(100).default(70),
    }),
  }),
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
    }),
  }),
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
        .default(['payment', 'transfer', 'profile.update', 'security.update', 'admin']),
      timeWindow: z
        .number()
        .int()
        .positive()
        .default(15 * 60), // 15 minutes
    }),
  }),
  continuousAuth: z.object({
    enabled: z.boolean().default(true),
    monitoringInterval: z
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
  }),
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
  }),
});

// Parse and validate environment variables
const rawConfig = {
  scoring: {
    defaultScore: env.getNumber('RISK_DEFAULT_SCORE'),
    thresholds: {
      low: env.getNumber('RISK_THRESHOLD_LOW'),
      medium: env.getNumber('RISK_THRESHOLD_MEDIUM'),
      high: env.getNumber('RISK_THRESHOLD_HIGH'),
    },
    weights: {
      ipReputation: env.getNumber('RISK_WEIGHT_IP_REPUTATION'),
      geolocation: env.getNumber('RISK_WEIGHT_GEOLOCATION'),
      deviceFingerprint: env.getNumber('RISK_WEIGHT_DEVICE_FINGERPRINT'),
      userBehavior: env.getNumber('RISK_WEIGHT_USER_BEHAVIOR'),
      timePattern: env.getNumber('RISK_WEIGHT_TIME_PATTERN'),
      threatIntelligence: env.getNumber('RISK_WEIGHT_THREAT_INTELLIGENCE'),
    },
  },
  ipReputation: {
    enabled: env.getBoolean('RISK_IP_REPUTATION_ENABLED'),
    providers: env.get('RISK_IP_REPUTATION_PROVIDERS')?.split(',') as any,
    cacheTime: env.getNumber('RISK_IP_REPUTATION_CACHE_TIME'),
    thresholds: {
      suspicious: env.getNumber('RISK_IP_REPUTATION_THRESHOLD_SUSPICIOUS'),
      malicious: env.getNumber('RISK_IP_REPUTATION_THRESHOLD_MALICIOUS'),
    },
  },
  geolocation: {
    enabled: env.getBoolean('RISK_GEOLOCATION_ENABLED'),
    providers: env.get('RISK_GEOLOCATION_PROVIDERS')?.split(',') as any,
    cacheTime: env.getNumber('RISK_GEOLOCATION_CACHE_TIME'),
    riskFactors: {
      countryChange: env.getNumber('RISK_GEOLOCATION_FACTOR_COUNTRY_CHANGE'),
      impossibleTravel: env.getNumber('RISK_GEOLOCATION_FACTOR_IMPOSSIBLE_TRAVEL'),
      highRiskCountry: env.getNumber('RISK_GEOLOCATION_FACTOR_HIGH_RISK_COUNTRY'),
      vpnDetected: env.getNumber('RISK_GEOLOCATION_FACTOR_VPN_DETECTED'),
      torDetected: env.getNumber('RISK_GEOLOCATION_FACTOR_TOR_DETECTED'),
      proxyDetected: env.getNumber('RISK_GEOLOCATION_FACTOR_PROXY_DETECTED'),
    },
    highRiskCountries: env.get('RISK_GEOLOCATION_HIGH_RISK_COUNTRIES')?.split(','),
  },
  deviceFingerprint: {
    enabled: env.getBoolean('RISK_DEVICE_FINGERPRINT_ENABLED'),
    components: env.get('RISK_DEVICE_FINGERPRINT_COMPONENTS')?.split(',') as any,
    riskFactors: {
      newDevice: env.getNumber('RISK_DEVICE_FINGERPRINT_FACTOR_NEW_DEVICE'),
      suspiciousDevice: env.getNumber('RISK_DEVICE_FINGERPRINT_FACTOR_SUSPICIOUS_DEVICE'),
      multipleAccounts: env.getNumber('RISK_DEVICE_FINGERPRINT_FACTOR_MULTIPLE_ACCOUNTS'),
      deviceSpoofing: env.getNumber('RISK_DEVICE_FINGERPRINT_FACTOR_DEVICE_SPOOFING'),
    },
    trustDeviceDuration: env.getNumber('RISK_DEVICE_FINGERPRINT_TRUST_DURATION'),
  },
  userBehavior: {
    enabled: env.getBoolean('RISK_USER_BEHAVIOR_ENABLED'),
    analysisWindow: env.getNumber('RISK_USER_BEHAVIOR_ANALYSIS_WINDOW'),
    minDataPoints: env.getNumber('RISK_USER_BEHAVIOR_MIN_DATA_POINTS'),
    riskFactors: {
      unusualLoginTime: env.getNumber('RISK_USER_BEHAVIOR_FACTOR_UNUSUAL_LOGIN_TIME'),
      unusualLoginLocation: env.getNumber('RISK_USER_BEHAVIOR_FACTOR_UNUSUAL_LOGIN_LOCATION'),
      unusualLoginFrequency: env.getNumber('RISK_USER_BEHAVIOR_FACTOR_UNUSUAL_LOGIN_FREQUENCY'),
      unusualActivityPattern: env.getNumber('RISK_USER_BEHAVIOR_FACTOR_UNUSUAL_ACTIVITY_PATTERN'),
      rapidAccountSwitching: env.getNumber('RISK_USER_BEHAVIOR_FACTOR_RAPID_ACCOUNT_SWITCHING'),
    },
  },
  timePattern: {
    enabled: env.getBoolean('RISK_TIME_PATTERN_ENABLED'),
    timeWindowHours: env.getNumber('RISK_TIME_PATTERN_WINDOW_HOURS'),
    riskFactors: {
      offHoursLogin: env.getNumber('RISK_TIME_PATTERN_FACTOR_OFF_HOURS_LOGIN'),
      irregularPattern: env.getNumber('RISK_TIME_PATTERN_FACTOR_IRREGULAR_PATTERN'),
      highFrequencyLogin: env.getNumber('RISK_TIME_PATTERN_FACTOR_HIGH_FREQUENCY_LOGIN'),
      accountSwitching: env.getNumber('RISK_TIME_PATTERN_FACTOR_ACCOUNT_SWITCHING'),
    },
  },
  threatIntelligence: {
    enabled: env.getBoolean('RISK_THREAT_INTELLIGENCE_ENABLED'),
    providers: env.get('RISK_THREAT_INTELLIGENCE_PROVIDERS')?.split(',') as any,
    cacheTime: env.getNumber('RISK_THREAT_INTELLIGENCE_CACHE_TIME'),
    riskFactors: {
      knownThreatActor: env.getNumber('RISK_THREAT_INTELLIGENCE_FACTOR_KNOWN_THREAT_ACTOR'),
      compromisedCredentials: env.getNumber(
        'RISK_THREAT_INTELLIGENCE_FACTOR_COMPROMISED_CREDENTIALS'
      ),
      malwareDetected: env.getNumber('RISK_THREAT_INTELLIGENCE_FACTOR_MALWARE_DETECTED'),
      botnetActivity: env.getNumber('RISK_THREAT_INTELLIGENCE_FACTOR_BOTNET_ACTIVITY'),
      phishingAttempt: env.getNumber('RISK_THREAT_INTELLIGENCE_FACTOR_PHISHING_ATTEMPT'),
    },
  },
  adaptiveAuth: {
    enabled: env.getBoolean('RISK_ADAPTIVE_AUTH_ENABLED'),
    riskLevels: {
      low: {
        requireMfa: env.getBoolean('RISK_ADAPTIVE_AUTH_LOW_REQUIRE_MFA'),
        allowRememberDevice: env.getBoolean('RISK_ADAPTIVE_AUTH_LOW_ALLOW_REMEMBER_DEVICE'),
        sessionDuration: env.getNumber('RISK_ADAPTIVE_AUTH_LOW_SESSION_DURATION'),
        allowedActions: env.get('RISK_ADAPTIVE_AUTH_LOW_ALLOWED_ACTIONS')?.split(','),
      },
      medium: {
        requireMfa: env.getBoolean('RISK_ADAPTIVE_AUTH_MEDIUM_REQUIRE_MFA'),
        allowRememberDevice: env.getBoolean('RISK_ADAPTIVE_AUTH_MEDIUM_ALLOW_REMEMBER_DEVICE'),
        sessionDuration: env.getNumber('RISK_ADAPTIVE_AUTH_MEDIUM_SESSION_DURATION'),
        allowedActions: env.get('RISK_ADAPTIVE_AUTH_MEDIUM_ALLOWED_ACTIONS')?.split(','),
      },
      high: {
        requireMfa: env.getBoolean('RISK_ADAPTIVE_AUTH_HIGH_REQUIRE_MFA'),
        allowRememberDevice: env.getBoolean('RISK_ADAPTIVE_AUTH_HIGH_ALLOW_REMEMBER_DEVICE'),
        sessionDuration: env.getNumber('RISK_ADAPTIVE_AUTH_HIGH_SESSION_DURATION'),
        allowedActions: env.get('RISK_ADAPTIVE_AUTH_HIGH_ALLOWED_ACTIONS')?.split(','),
      },
      critical: {
        requireMfa: env.getBoolean('RISK_ADAPTIVE_AUTH_CRITICAL_REQUIRE_MFA'),
        allowRememberDevice: env.getBoolean('RISK_ADAPTIVE_AUTH_CRITICAL_ALLOW_REMEMBER_DEVICE'),
        sessionDuration: env.getNumber('RISK_ADAPTIVE_AUTH_CRITICAL_SESSION_DURATION'),
        allowedActions: env.get('RISK_ADAPTIVE_AUTH_CRITICAL_ALLOWED_ACTIONS')?.split(','),
        requireAdditionalVerification: env.getBoolean(
          'RISK_ADAPTIVE_AUTH_CRITICAL_REQUIRE_ADDITIONAL_VERIFICATION'
        ),
      },
    },
    stepUpAuth: {
      enabled: env.getBoolean('RISK_STEP_UP_AUTH_ENABLED'),
      sensitiveActions: env.get('RISK_STEP_UP_AUTH_SENSITIVE_ACTIONS')?.split(','),
      timeWindow: env.getNumber('RISK_STEP_UP_AUTH_TIME_WINDOW'),
    },
  },
  continuousAuth: {
    enabled: env.getBoolean('RISK_CONTINUOUS_AUTH_ENABLED'),
    monitoringInterval: env.getNumber('RISK_CONTINUOUS_AUTH_MONITORING_INTERVAL'),
    maxRiskIncrement: env.getNumber('RISK_CONTINUOUS_AUTH_MAX_RISK_INCREMENT'),
    riskDecayRate: env.getNumber('RISK_CONTINUOUS_AUTH_RISK_DECAY_RATE'),
    riskFactors: {
      inactivityThreshold: env.getNumber('RISK_CONTINUOUS_AUTH_INACTIVITY_THRESHOLD'),
      suspiciousActivityThreshold: env.getNumber(
        'RISK_CONTINUOUS_AUTH_SUSPICIOUS_ACTIVITY_THRESHOLD'
      ),
      locationChangeThreshold: env.getNumber('RISK_CONTINUOUS_AUTH_LOCATION_CHANGE_THRESHOLD'),
    },
  },
  machineLearning: {
    enabled: env.getBoolean('RISK_ML_ENABLED'),
    modelUpdateInterval: env.getNumber('RISK_ML_MODEL_UPDATE_INTERVAL'),
    minTrainingData: env.getNumber('RISK_ML_MIN_TRAINING_DATA'),
    anomalyThreshold: env.getNumber('RISK_ML_ANOMALY_THRESHOLD'),
    featureImportance: {
      loginTime: env.getNumber('RISK_ML_FEATURE_IMPORTANCE_LOGIN_TIME'),
      loginLocation: env.getNumber('RISK_ML_FEATURE_IMPORTANCE_LOGIN_LOCATION'),
      deviceType: env.getNumber('RISK_ML_FEATURE_IMPORTANCE_DEVICE_TYPE'),
      ipAddress: env.getNumber('RISK_ML_FEATURE_IMPORTANCE_IP_ADDRESS'),
      userAgent: env.getNumber('RISK_ML_FEATURE_IMPORTANCE_USER_AGENT'),
      interactionPattern: env.getNumber('RISK_ML_FEATURE_IMPORTANCE_INTERACTION_PATTERN'),
    },
  },
};

// Validate and export config
export const riskConfig = validateConfig(riskConfigSchema, rawConfig);

// Export config type
export type RiskConfig = typeof riskConfig;
