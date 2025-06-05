/**
 * Risk assessment and adaptive authentication configuration
 */
export const riskConfig = {
  /**
   * IP reputation risk assessment configuration
   */
  ipReputation: {
    enabled: true,
    providers: ['local', 'abuseipdb', 'ipqualityscore', 'ipinfo'],
    cacheTime: 3600, // Cache time in seconds
    thresholds: {
      low: 20,
      suspicious: 50,
      high: 75,
    },
  },

  /**
   * Geolocation risk assessment configuration
   */
  geolocation: {
    enabled: true,
    providers: ['local', 'ipinfo', 'maxmind', 'ipgeolocation'],
    cacheTime: 3600, // Cache time in seconds
    highRiskCountries: ['KP', 'IR', 'SY', 'SD', 'CU'], // ISO country codes
    riskFactors: {
      vpnDetected: 60,
      torDetected: 80,
      proxyDetected: 70,
      highRiskCountry: 75,
      countryChange: 50,
      impossibleTravel: 90,
    },
  },

  /**
   * Device fingerprint risk assessment configuration
   */
  deviceFingerprint: {
    enabled: true,
    components: [
      'userAgent',
      'language',
      'colorDepth',
      'deviceMemory',
      'hardwareConcurrency',
      'screenResolution',
      'availableScreenResolution',
      'timezoneOffset',
      'timezone',
      'sessionStorage',
      'localStorage',
      'indexedDb',
      'addBehavior',
      'openDatabase',
      'cpuClass',
      'platform',
      'plugins',
      'canvas',
      'webgl',
      'webglVendorAndRenderer',
      'adBlock',
      'hasLiedLanguages',
      'hasLiedResolution',
      'hasLiedOs',
      'hasLiedBrowser',
      'touchSupport',
      'fonts',
      'audio',
    ],
    riskFactors: {
      deviceSpoofing: 80,
      newDevice: 50,
      suspiciousDevice: 70,
      multipleAccounts: 60,
    },
    trustDeviceDuration: 30 * 24 * 60 * 60, // 30 days in seconds
  },

  /**
   * User behavior risk assessment configuration
   */
  userBehavior: {
    enabled: true,
    minDataPoints: 5,
    analysisWindow: 30 * 24 * 60 * 60, // 30 days in seconds
    riskFactors: {
      unusualLoginTime: 50,
      unusualLoginLocation: 60,
      unusualLoginFrequency: 40,
      unusualActivityPattern: 55,
      rapidAccountSwitching: 70,
    },
  },

  /**
   * Time pattern risk assessment configuration
   */
  timePattern: {
    enabled: true,
    windowHours: 720, // 30 days
    riskFactors: {
      offHoursLogin: 50,
      irregularPattern: 60,
      highFrequencyLogin: 40,
      accountSwitching: 70,
    },
  },

  /**
   * Threat intelligence risk assessment configuration
   */
  threatIntelligence: {
    enabled: true,
    providers: ['local', 'virustotal', 'abuseipdb', 'haveibeenpwned'],
    cacheTime: 3600, // Cache time in seconds
    riskFactors: {
      knownThreatActor: 90,
      compromisedCredentials: 80,
      botnetActivity: 85,
      phishingAttempt: 75,
      attackPattern: 70,
    },
  },

  /**
   * Machine learning risk assessment configuration
   */
  machineLeaning: {
    enabled: true,
    minDataPoints: 10,
    modelUpdateInterval: 24 * 60 * 60, // 24 hours in seconds
    featureImportance: {
      ipReputation: 0.1,
      geolocation: 0.15,
      deviceFingerprint: 0.2,
      userBehavior: 0.25,
      timePattern: 0.1,
      threatIntelligence: 0.2,
    },
  },

  /**
   * Risk scoring configuration
   */
  scoring: {
    defaultScore: 20,
    weights: {
      ipReputation: 0.15,
      geolocation: 0.2,
      deviceFingerprint: 0.2,
      userBehavior: 0.25,
      timePattern: 0.1,
      threatIntelligence: 0.1,
    },
    thresholds: {
      low: 30,
      medium: 60,
      high: 80,
    },
  },

  /**
   * Adaptive authentication configuration
   */
  adaptiveAuth: {
    enabled: true,
    riskLevels: {
      low: {
        requireMfa: false,
        allowRememberDevice: true,
        sessionDuration: 24 * 60 * 60, // 24 hours in seconds
        allowedActions: ['all'],
      },
      medium: {
        requireMfa: true,
        allowRememberDevice: true,
        sessionDuration: 12 * 60 * 60, // 12 hours in seconds
        allowedActions: ['all'],
      },
      high: {
        requireMfa: true,
        allowRememberDevice: false,
        sessionDuration: 1 * 60 * 60, // 1 hour in seconds
        allowedActions: ['read', 'basic'],
      },
      critical: {
        requireMfa: true,
        allowRememberDevice: false,
        sessionDuration: 30 * 60, // 30 minutes in seconds
        allowedActions: ['read'],
        requireAdditionalVerification: true,
      },
    },
    stepUpAuth: {
      enabled: true,
      sensitiveActions: [
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
    },
  },

  /**
   * Continuous authentication configuration
   */
  continuousAuth: {
    enabled: true,
    assessmentInterval: 5 * 60, // 5 minutes in seconds
    riskDecayRate: 0.1, // 10% decay rate per assessment
    maxRiskIncrement: 20, // Maximum risk score increase per assessment
    triggerEvents: ['pageNavigation', 'sensitiveAction', 'idleTimeout', 'ipChange', 'deviceChange'],
  },

  /**
   * Risk rules configuration
   */
  rules: {
    enabled: true,
    evaluationOrder: ['whitelist', 'blacklist', 'custom'],
    defaultAction: 'allow',
  },

  /**
   * Risk event handling configuration
   */
  events: {
    notifyUser: {
      enabled: true,
      events: [
        'risk.high.detected',
        'risk.critical.detected',
        'risk.location.change.detected',
        'risk.device.change.detected',
        'risk.compromised.credentials.detected',
      ],
    },
    notifyAdmin: {
      enabled: true,
      events: [
        'risk.critical.detected',
        'risk.threat.detected',
        'risk.impossible.travel.detected',
        'risk.botnet.activity.detected',
      ],
    },
  },
};
