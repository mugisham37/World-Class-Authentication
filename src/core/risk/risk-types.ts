/**
 * Risk level enum
 */
export enum RiskLevel {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical",
}

/**
 * Risk factor enum
 */
export enum RiskFactor {
  IP_REPUTATION = "ipReputation",
  GEOLOCATION = "geolocation",
  DEVICE_FINGERPRINT = "deviceFingerprint",
  USER_BEHAVIOR = "userBehavior",
  TIME_PATTERN = "timePattern",
  THREAT_INTELLIGENCE = "threatIntelligence",
  MACHINE_LEARNING = "machineLearning",
}

/**
 * Risk assessment result interface
 */
export interface RiskAssessmentResult {
  id: string
  userId: string | null
  riskScore: number
  riskLevel: RiskLevel
  riskFactors: Record<RiskFactor, number>
  actions: Record<string, any>
  timestamp: Date
}

/**
 * Risk rule interface
 */
export interface RiskRule {
  id: string
  name: string
  description: string
  enabled: boolean
  riskFactor: RiskFactor
  condition: RiskRuleCondition
  score: number
  metadata?: Record<string, any>
}

/**
 * Risk rule condition interface
 */
export interface RiskRuleCondition {
  type: RiskRuleConditionType
  field: string
  operator: RiskRuleOperator
  value: any
  children?: RiskRuleCondition[]
}

/**
 * Risk rule condition type enum
 */
export enum RiskRuleConditionType {
  SIMPLE = "simple",
  AND = "and",
  OR = "or",
  NOT = "not",
}

/**
 * Risk rule operator enum
 */
export enum RiskRuleOperator {
  EQUALS = "equals",
  NOT_EQUALS = "notEquals",
  GREATER_THAN = "greaterThan",
  LESS_THAN = "lessThan",
  CONTAINS = "contains",
  NOT_CONTAINS = "notContains",
  STARTS_WITH = "startsWith",
  ENDS_WITH = "endsWith",
  MATCHES = "matches",
  IN = "in",
  NOT_IN = "notIn",
  EXISTS = "exists",
  NOT_EXISTS = "notExists",
}

/**
 * Geolocation data interface
 */
export interface GeolocationData {
  ip: string
  country: string
  countryCode: string
  region: string
  regionCode: string
  city: string
  postalCode: string
  latitude: number
  longitude: number
  timezone: string
  isp: string
  org: string
  asn: string
  proxy: boolean
  vpn: boolean
  tor: boolean
  hosting: boolean
  risk: number
}

/**
 * Device fingerprint data interface
 */
export interface DeviceFingerprintData {
  hash: string
  components: Record<string, any>
  userAgent: string
  browser: {
    name: string
    version: string
    language: string
  }
  os: {
    name: string
    version: string
    platform: string
  }
  device: {
    type: string
    brand: string
    model: string
    touch: boolean
  }
  screen: {
    width: number
    height: number
    colorDepth: number
  }
  network: {
    connection: string
    downlink: number
    rtt: number
  }
  features: Record<string, boolean>
  anomalies: string[]
}

/**
 * User behavior profile interface
 */
export interface UserBehaviorProfile {
  userId: string
  loginTimes: {
    hourDistribution: number[]
    dayDistribution: number[]
  }
  loginLocations: {
    countries: Record<string, number>
    regions: Record<string, number>
    cities: Record<string, number>
    coordinates: Array<[number, number]>
  }
  devices: {
    browsers: Record<string, number>
    operatingSystems: Record<string, number>
    deviceTypes: Record<string, number>
  }
  activityPatterns: {
    sessionDuration: {
      mean: number
      stdDev: number
    }
    actionsPerSession: {
      mean: number
      stdDev: number
    }
    actionTypes: Record<string, number>
  }
  lastUpdated: Date
  dataPoints: number
}

/**
 * Threat intelligence data interface
 */
export interface ThreatIntelligenceData {
  ip?: {
    isKnownBad: boolean
    isTor: boolean
    isProxy: boolean
    isVpn: boolean
    isBot: boolean
    score: number
    categories: string[]
    source: string
  }
  email?: {
    isCompromised: boolean
    breachCount: number
    lastBreachDate: Date | null
    score: number
    source: string
  }
  domain?: {
    isKnownBad: boolean
    isMalicious: boolean
    isPhishing: boolean
    score: number
    categories: string[]
    source: string
  }
  hash?: {
    isKnownBad: boolean
    isMalware: boolean
    score: number
    categories: string[]
    source: string
  }
}
