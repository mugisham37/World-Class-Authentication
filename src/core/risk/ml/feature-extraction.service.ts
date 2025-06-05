import { Injectable } from "@tsed/di"
import { logger } from "../../../infrastructure/logging/logger"
import type { UserLoginHistoryRepository } from "../../../data/repositories/user-login-history.repository"
import type { UserRepository } from "../../../data/repositories/user.repository"
import type { SessionRepository } from "../../../data/repositories/session.repository"
import type { AuditLogRepository } from "../../../data/repositories/audit-log.repository"

/**
 * Feature extraction service for machine learning risk assessment
 * Extracts features from authentication data for use in ML models
 */
@Injectable()
export class FeatureExtractionService {
  constructor(
    private userLoginHistoryRepository: UserLoginHistoryRepository,
    private userRepository: UserRepository,
    private sessionRepository: SessionRepository,
    private auditLogRepository: AuditLogRepository,
  ) {}

  /**
   * Extract features for a user's authentication attempt
   * @param userId User ID
   * @param context Authentication context
   * @returns Extracted features for ML processing
   */
  async extractAuthenticationFeatures(userId: string, context: Record<string, any>): Promise<Record<string, any>> {
    try {
      logger.debug("Extracting authentication features", { userId })

      // Get user's login history
      const loginHistory = await this.userLoginHistoryRepository.findRecentByUserId(userId, 20)

      // Get user's active sessions
      const activeSessions = await this.sessionRepository.findActiveByUserId(userId)

      // Get user's recent audit logs
      const auditLogs = await this.auditLogRepository.findRecentByUserId(userId, 50)

      // Get user data
      const user = await this.userRepository.findById(userId)

      // Extract temporal features
      const temporalFeatures = this.extractTemporalFeatures(loginHistory)

      // Extract location features
      const locationFeatures = this.extractLocationFeatures(loginHistory, context)

      // Extract device features
      const deviceFeatures = this.extractDeviceFeatures(loginHistory, context)

      // Extract behavior features
      const behaviorFeatures = this.extractBehaviorFeatures(auditLogs, context)

      // Extract session features
      const sessionFeatures = this.extractSessionFeatures(activeSessions, context)

      // Extract user account features
      const userFeatures = this.extractUserFeatures(user)

      // Combine all features
      const features = {
        ...temporalFeatures,
        ...locationFeatures,
        ...deviceFeatures,
        ...behaviorFeatures,
        ...sessionFeatures,
        ...userFeatures,
        timestamp: Date.now(),
      }

      logger.debug("Feature extraction completed", { userId, featureCount: Object.keys(features).length })

      return features
    } catch (error) {
      logger.error("Error extracting authentication features", { error, userId })
      // Return basic features on error
      return {
        error: true,
        timestamp: Date.now(),
      }
    }
  }

  /**
   * Extract temporal features from login history
   * @param loginHistory User's login history
   * @returns Temporal features
   */
  private extractTemporalFeatures(loginHistory: any[]): Record<string, any> {
    // Initialize features
    const features: Record<string, any> = {
      login_frequency_daily: 0,
      login_frequency_weekly: 0,
      login_time_variance: 0,
      login_day_variance: 0,
      login_interval_mean: 0,
      login_interval_std: 0,
      weekend_login_ratio: 0,
      business_hours_login_ratio: 0,
    }

    if (!loginHistory || loginHistory.length === 0) {
      return features
    }

    try {
      // Current time
      const now = new Date()

      // Calculate login frequencies
      const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000)
      const oneWeekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)

      features.login_frequency_daily = loginHistory.filter(
        (login) => login && login.timestamp && login.timestamp >= oneDayAgo,
      ).length
      features.login_frequency_weekly = loginHistory.filter(
        (login) => login && login.timestamp && login.timestamp >= oneWeekAgo,
      ).length

      // Calculate login time variance
      const loginHours = loginHistory
        .filter((login) => login && login.timestamp)
        .map((login) => login.timestamp.getHours())
      features.login_time_variance = this.calculateVariance(loginHours)

      // Calculate login day variance
      const loginDays = loginHistory
        .filter((login) => login && login.timestamp)
        .map((login) => login.timestamp.getDay())
      features.login_day_variance = this.calculateVariance(loginDays)

      // Calculate login intervals
      const intervals: number[] = []
      for (let i = 1; i < loginHistory.length; i++) {
        if (
          loginHistory[i] &&
          loginHistory[i].timestamp &&
          loginHistory[i - 1] &&
          loginHistory[i - 1].timestamp
        ) {
          const interval =
            (loginHistory[i - 1].timestamp.getTime() - loginHistory[i].timestamp.getTime()) / (60 * 60 * 1000) // hours
          intervals.push(interval)
        }
      }

      if (intervals.length > 0) {
        features.login_interval_mean = this.calculateMean(intervals)
        features.login_interval_std = this.calculateStandardDeviation(intervals)
      }

      // Calculate weekend and business hours ratios
      const weekendLogins = loginHistory.filter(
        (login) => login && login.timestamp && (login.timestamp.getDay() === 0 || login.timestamp.getDay() === 6),
      ).length
      features.weekend_login_ratio = loginHistory.length > 0 ? weekendLogins / loginHistory.length : 0

      const businessHoursLogins = loginHistory.filter(
        (login) =>
          login &&
          login.timestamp &&
          login.timestamp.getHours() >= 9 &&
          login.timestamp.getHours() < 17 &&
          login.timestamp.getDay() >= 1 &&
          login.timestamp.getDay() <= 5,
      ).length
      features.business_hours_login_ratio = loginHistory.length > 0 ? businessHoursLogins / loginHistory.length : 0

      return features
    } catch (error) {
      logger.error("Error extracting temporal features", { error })
      return features
    }
  }

  /**
   * Extract location features from login history
   * @param loginHistory User's login history
   * @param context Current authentication context
   * @returns Location features
   */
  private extractLocationFeatures(loginHistory: any[], context: Record<string, any>): Record<string, any> {
    // Initialize features
    const features: Record<string, any> = {
      location_diversity: 0,
      location_entropy: 0,
      is_new_country: false,
      is_new_region: false,
      is_new_city: false,
      distance_from_last_login: 0,
      max_travel_speed: 0,
      high_risk_location: false,
      vpn_detected: false,
      proxy_detected: false,
      tor_detected: false,
    }

    if (!loginHistory || loginHistory.length === 0 || !context) {
      return features
    }

    try {
      // Extract unique locations
      const countries = new Set<string>()
      const regions = new Set<string>()
      const cities = new Set<string>()

      loginHistory.forEach((login) => {
        if (login && login.countryCode) countries.add(login.countryCode)
        if (login && login.regionCode) regions.add(login.regionCode)
        if (login && login.city) cities.add(login.city)
      })

      features.location_diversity = countries.size + regions.size + cities.size

      // Calculate location entropy (frequency-based)
      const countryFrequency: Record<string, number> = {}
      loginHistory.forEach((login) => {
        if (login && login.countryCode) {
          countryFrequency[login.countryCode] = (countryFrequency[login.countryCode] || 0) + 1
        }
      })

      features.location_entropy = this.calculateEntropy(
        Object.values(countryFrequency).map((count) => count / loginHistory.length),
      )

      // Check if current location is new
      if (context.countryCode && loginHistory.length > 0) {
        features.is_new_country = !loginHistory.some((login) => login && login.countryCode === context.countryCode)
      }

      if (context.regionCode && loginHistory.length > 0) {
        features.is_new_region = !loginHistory.some((login) => login && login.regionCode === context.regionCode)
      }

      if (context.city && loginHistory.length > 0) {
        features.is_new_city = !loginHistory.some((login) => login && login.city === context.city)
      }

      // Calculate distance from last login
      if (
        context.latitude &&
        context.longitude &&
        loginHistory[0] &&
        loginHistory[0].latitude &&
        loginHistory[0].longitude
      ) {
        features.distance_from_last_login = this.calculateDistance(
          context.latitude,
          context.longitude,
          loginHistory[0].latitude,
          loginHistory[0].longitude,
        )
      }

      // Calculate maximum travel speed
      if (context.latitude && context.longitude && loginHistory.length > 0) {
        let maxSpeed = 0
        for (const login of loginHistory) {
          if (login && login.latitude && login.longitude && login.timestamp) {
            const distance = this.calculateDistance(
              context.latitude,
              context.longitude,
              login.latitude,
              login.longitude,
            )
            const timeDiff = (Date.now() - login.timestamp.getTime()) / (60 * 60 * 1000) // hours
            if (timeDiff > 0) {
              const speed = distance / timeDiff
              maxSpeed = Math.max(maxSpeed, speed)
            }
          }
        }
        features.max_travel_speed = maxSpeed
      }

      // Set high-risk location flag
      features.high_risk_location = context.highRiskLocation || false

      // Set VPN, proxy, and Tor flags
      features.vpn_detected = context.vpn || false
      features.proxy_detected = context.proxy || false
      features.tor_detected = context.tor || false

      return features
    } catch (error) {
      logger.error("Error extracting location features", { error })
      return features
    }
  }

  /**
   * Extract device features from login history
   * @param loginHistory User's login history
   * @param context Current authentication context
   * @returns Device features
   */
  private extractDeviceFeatures(loginHistory: any[], context: Record<string, any>): Record<string, any> {
    // Initialize features
    const features: Record<string, any> = {
      device_diversity: 0,
      is_new_device: true,
      is_new_browser: true,
      is_new_os: true,
      device_age: 0,
      device_usage_frequency: 0,
      device_entropy: 0,
      multiple_devices_short_period: false,
      suspicious_device_characteristics: false,
    }

    if (!loginHistory || loginHistory.length === 0 || !context || !context.deviceFingerprint) {
      return features
    }

    try {
      // Extract unique devices, browsers, and operating systems
      const devices = new Set<string>()
      const browsers = new Set<string>()
      const operatingSystems = new Set<string>()

      loginHistory.forEach((login) => {
        if (login && login.deviceFingerprint) devices.add(login.deviceFingerprint)
        if (login && login.userAgent) {
          const browserInfo = this.extractBrowserInfo(login.userAgent)
          if (browserInfo.browser) browsers.add(browserInfo.browser)
          if (browserInfo.os) operatingSystems.add(browserInfo.os)
        }
      })

      features.device_diversity = devices.size

      // Check if current device is new
      features.is_new_device = !loginHistory.some(
        (login) => login && login.deviceFingerprint === context.deviceFingerprint,
      )

      // Check if current browser is new
      if (context.userAgent) {
        const currentBrowserInfo = this.extractBrowserInfo(context.userAgent)
        features.is_new_browser = !loginHistory.some((login) => {
          if (!login || !login.userAgent) return false
          const loginBrowserInfo = this.extractBrowserInfo(login.userAgent)
          return loginBrowserInfo.browser === currentBrowserInfo.browser
        })

        // Check if current OS is new
        features.is_new_os = !loginHistory.some((login) => {
          if (!login || !login.userAgent) return false
          const loginBrowserInfo = this.extractBrowserInfo(login.userAgent)
          return loginBrowserInfo.os === currentBrowserInfo.os
        })
      }

      // Calculate device age (days since first seen)
      const deviceHistory = loginHistory.filter(
        (login) => login && login.deviceFingerprint === context.deviceFingerprint,
      )
      if (deviceHistory.length > 0) {
        const firstSeen = deviceHistory.reduce((oldest, login) => {
          return login && login.timestamp && (!oldest || login.timestamp < oldest) ? login.timestamp : oldest
        }, null)

        if (firstSeen) {
          features.device_age = (Date.now() - firstSeen.getTime()) / (24 * 60 * 60 * 1000) // days
        }
      }

      // Calculate device usage frequency
      features.device_usage_frequency = deviceHistory.length

      // Calculate device entropy (frequency-based)
      const deviceFrequency: Record<string, number> = {}
      loginHistory.forEach((login) => {
        if (login && login.deviceFingerprint) {
          deviceFrequency[login.deviceFingerprint] = (deviceFrequency[login.deviceFingerprint] || 0) + 1
        }
      })

      features.device_entropy = this.calculateEntropy(
        Object.values(deviceFrequency).map((count) => count / loginHistory.length),
      )

      // Check for multiple devices in a short period
      const recentLogins = loginHistory.filter(
        (login) => login && login.timestamp && login.timestamp >= new Date(Date.now() - 24 * 60 * 60 * 1000),
      )
      const recentDevices = new Set(
        recentLogins.filter((login) => login && login.deviceFingerprint).map((login) => login.deviceFingerprint),
      )
      features.multiple_devices_short_period = recentDevices.size > 2

      // Check for suspicious device characteristics
      features.suspicious_device_characteristics = context.suspiciousDevice || false

      return features
    } catch (error) {
      logger.error("Error extracting device features", { error })
      return features
    }
  }

  /**
   * Extract behavior features from audit logs
   * @param auditLogs User's audit logs
   * @param context Current authentication context
   * @returns Behavior features
   */
  private extractBehaviorFeatures(auditLogs: any[], context: Record<string, any>): Record<string, any> {
    // Initialize features
    const features: Record<string, any> = {
      action_diversity: 0,
      action_entropy: 0,
      failed_login_ratio: 0,
      password_reset_frequency: 0,
      mfa_challenge_frequency: 0,
      suspicious_action_frequency: 0,
      session_duration_mean: 0,
      session_duration_std: 0,
      pages_per_session_mean: 0,
      inactive_period_before_login: 0,
    }

    if (!auditLogs || auditLogs.length === 0) {
      return features
    }

    try {
      // Extract unique actions
      const actions = new Set<string>()
      auditLogs.forEach((log) => {
        if (log && log.action) actions.add(log.action)
      })

      features.action_diversity = actions.size

      // Calculate action entropy (frequency-based)
      const actionFrequency: Record<string, number> = {}
      auditLogs.forEach((log) => {
        if (log && log.action) {
          actionFrequency[log.action] = (actionFrequency[log.action] || 0) + 1
        }
      })

      features.action_entropy = this.calculateEntropy(
        Object.values(actionFrequency).map((count) => count / auditLogs.length),
      )

      // Calculate failed login ratio
      const loginAttempts = auditLogs.filter((log) => log && log.action === "LOGIN_ATTEMPT")
      const failedLogins = auditLogs.filter((log) => log && log.action === "LOGIN_FAILED")
      features.failed_login_ratio = loginAttempts.length > 0 ? failedLogins.length / loginAttempts.length : 0

      // Calculate password reset frequency
      const passwordResets = auditLogs.filter((log) => log && log.action === "PASSWORD_RESET")
      features.password_reset_frequency = passwordResets.length

      // Calculate MFA challenge frequency
      const mfaChallenges = auditLogs.filter((log) => log && log.action === "MFA_CHALLENGE_GENERATED")
      features.mfa_challenge_frequency = mfaChallenges.length

      // Calculate suspicious action frequency
      const suspiciousActions = auditLogs.filter(
        (log) =>
          log &&
          (log.action === "SUSPICIOUS_ACTIVITY_DETECTED" ||
            log.action === "ACCOUNT_LOCKED" ||
            log.action === "BRUTE_FORCE_ATTEMPT"),
      )
      features.suspicious_action_frequency = suspiciousActions.length

      // Calculate session duration statistics
      const sessionDurations: number[] = []
      const sessionLogs = auditLogs.filter(
        (log) =>
          log &&
          (log.action === "SESSION_CREATED" || log.action === "SESSION_EXPIRED" || log.action === "SESSION_TERMINATED"),
      )

      // Group by session ID
      const sessionGroups: Record<string, any[]> = {}
      sessionLogs.forEach((log) => {
        if (log && log.metadata && log.metadata.sessionId) {
          const sessionId = log.metadata.sessionId
          if (!sessionGroups[sessionId]) {
            sessionGroups[sessionId] = []
          }
          sessionGroups[sessionId].push(log)
        }
      })

      // Calculate durations
      Object.values(sessionGroups).forEach((logs) => {
        const created = logs.find((log) => log && log.action === "SESSION_CREATED")
        const ended = logs.find(
          (log) => log && (log.action === "SESSION_EXPIRED" || log.action === "SESSION_TERMINATED"),
        )
        if (created && ended && created.timestamp && ended.timestamp) {
          const duration = (ended.timestamp.getTime() - created.timestamp.getTime()) / (60 * 1000) // minutes
          sessionDurations.push(duration)
        }
      })

      if (sessionDurations.length > 0) {
        features.session_duration_mean = this.calculateMean(sessionDurations)
        features.session_duration_std = this.calculateStandardDeviation(sessionDurations)
      }

      // Calculate pages per session
      const pagesPerSession: number[] = []
      Object.values(sessionGroups).forEach((logs) => {
        const pageViews = logs.filter((log) => log && log.action === "PAGE_VIEW").length
        if (pageViews > 0) {
          pagesPerSession.push(pageViews)
        }
      })

      if (pagesPerSession.length > 0) {
        features.pages_per_session_mean = this.calculateMean(pagesPerSession)
      }

      // Calculate inactive period before login
      const sortedLogs = [...auditLogs].sort((a, b) => {
        if (!a || !a.timestamp || !b || !b.timestamp) return 0
        return b.timestamp.getTime() - a.timestamp.getTime()
      })

      const lastActivity = sortedLogs[0]
      if (lastActivity && lastActivity.timestamp) {
        features.inactive_period_before_login = (Date.now() - lastActivity.timestamp.getTime()) / (60 * 60 * 1000) // hours
      }

      return features
    } catch (error) {
      logger.error("Error extracting behavior features", { error })
      return features
    }
  }

  /**
   * Extract session features from active sessions
   * @param activeSessions User's active sessions
   * @param context Current authentication context
   * @returns Session features
   */
  private extractSessionFeatures(activeSessions: any[], context: Record<string, any>): Record<string, any> {
    // Initialize features
    const features: Record<string, any> = {
      active_session_count: 0,
      concurrent_session_locations: 0,
      concurrent_session_devices: 0,
      session_location_entropy: 0,
      session_device_entropy: 0,
      has_overlapping_session: false,
      session_age_mean: 0,
      session_with_similar_ip: false,
      session_with_similar_device: false,
    }

    if (!activeSessions || activeSessions.length === 0 || !context) {
      return features
    }

    try {
      // Count active sessions
      features.active_session_count = activeSessions.length

      // Count unique locations and devices in active sessions
      const sessionCountries = new Set<string>()
      const sessionDevices = new Set<string>()

      activeSessions.forEach((session) => {
        if (session && session.countryCode) sessionCountries.add(session.countryCode)
        if (session && session.deviceFingerprint) sessionDevices.add(session.deviceFingerprint)
      })

      features.concurrent_session_locations = sessionCountries.size
      features.concurrent_session_devices = sessionDevices.size

      // Calculate location entropy for sessions
      const countryFrequency: Record<string, number> = {}
      activeSessions.forEach((session) => {
        if (session && session.countryCode) {
          countryFrequency[session.countryCode] = (countryFrequency[session.countryCode] || 0) + 1
        }
      })

      features.session_location_entropy = this.calculateEntropy(
        Object.values(countryFrequency).map((count) => count / activeSessions.length),
      )

      // Calculate device entropy for sessions
      const deviceFrequency: Record<string, number> = {}
      activeSessions.forEach((session) => {
        if (session && session.deviceFingerprint) {
          deviceFrequency[session.deviceFingerprint] = (deviceFrequency[session.deviceFingerprint] || 0) + 1
        }
      })

      features.session_device_entropy = this.calculateEntropy(
        Object.values(deviceFrequency).map((count) => count / activeSessions.length),
      )

      // Check for similar IP
      if (context.ipAddress) {
        const ipParts = context.ipAddress.split(".")
        if (ipParts.length === 4) {
          const ipPrefix = `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}`
          features.session_with_similar_ip = activeSessions.some((session) => {
            if (!session || !session.ipAddress) return false
            const sessionIpParts = session.ipAddress.split(".")
            if (sessionIpParts.length !== 4) return false
            const sessionIpPrefix = `${sessionIpParts[0]}.${sessionIpParts[1]}.${sessionIpParts[2]}`
            return sessionIpPrefix === ipPrefix && session.ipAddress !== context.ipAddress
          })
        }
      }

      // Check for similar device
      if (context.deviceFingerprint) {
        features.session_with_similar_device = activeSessions.some(
          (session) =>
            session &&
            session.deviceFingerprint &&
            session.deviceFingerprint !== context.deviceFingerprint &&
            this.calculateSimilarity(session.deviceFingerprint, context.deviceFingerprint) > 0.8,
        )
      }

      // Calculate mean session age
      const sessionAges = activeSessions
        .filter((session) => session && session.createdAt)
        .map((session) => (Date.now() - session.createdAt.getTime()) / (60 * 60 * 1000)) // hours

      if (sessionAges.length > 0) {
        features.session_age_mean = this.calculateMean(sessionAges)
      }

      // Check for has_overlapping_session
      features.has_overlapping_session = activeSessions.some((session) => {
        if (!session || !session.createdAt || !context.timestamp) return false
        const sessionStart = session.createdAt.getTime()
        const sessionEnd = session.expiresAt ? session.expiresAt.getTime() : sessionStart + 24 * 60 * 60 * 1000
        return (
          context.timestamp >= sessionStart &&
          context.timestamp <= sessionEnd &&
          session.deviceFingerprint !== context.deviceFingerprint
        )
      })

      return features
    } catch (error) {
      logger.error("Error extracting session features", { error })
      return features
    }
  }

  /**
   * Extract user account features
   * @param user User object
   * @returns User account features
   */
  private extractUserFeatures(user: any): Record<string, any> {
    // Initialize features
    const features: Record<string, any> = {
      account_age: 0,
      has_mfa: false,
      mfa_method_count: 0,
      password_age: 0,
      password_strength: 0,
      email_verified: false,
      phone_verified: false,
      is_admin: false,
      has_recovery_methods: false,
      recovery_method_count: 0,
      login_count: 0,
    }

    if (!user) {
      return features
    }

    try {
      // Calculate account age in days
      if (user.createdAt) {
        features.account_age = (Date.now() - user.createdAt.getTime()) / (24 * 60 * 60 * 1000)
      }

      // Check MFA status
      features.has_mfa = user.mfaEnabled || false
      features.mfa_method_count = user.mfaFactors ? user.mfaFactors.length : 0

      // Calculate password age in days
      if (user.passwordUpdatedAt) {
        features.password_age = (Date.now() - user.passwordUpdatedAt.getTime()) / (24 * 60 * 60 * 1000)
      }

      // Set password strength (if available)
      features.password_strength = user.passwordStrength || 0

      // Check verification status
      features.email_verified = user.emailVerified || false
      features.phone_verified = user.phoneVerified || false

      // Check admin status
      features.is_admin = user.isAdmin || false

      // Check recovery methods
      features.has_recovery_methods = user.recoveryMethods && user.recoveryMethods.length > 0
      features.recovery_method_count = user.recoveryMethods ? user.recoveryMethods.length : 0

      // Set login count
      features.login_count = user.loginCount || 0

      return features
    } catch (error) {
      logger.error("Error extracting user features", { error })
      return features
    }
  }

  /**
   * Calculate the mean of an array of numbers
   * @param values Array of numbers
   * @returns Mean value
   */
  private calculateMean(values: number[]): number {
    if (!values || values.length === 0) return 0
    return values.reduce((sum, value) => sum + value, 0) / values.length
  }

  /**
   * Calculate the variance of an array of numbers
   * @param values Array of numbers
   * @returns Variance
   */
  private calculateVariance(values: number[]): number {
    if (!values || values.length === 0) return 0
    const mean = this.calculateMean(values)
    return this.calculateMean(values.map((value) => Math.pow(value - mean, 2)))
  }

  /**
   * Calculate the standard deviation of an array of numbers
   * @param values Array of numbers
   * @returns Standard deviation
   */
  private calculateStandardDeviation(values: number[]): number {
    return Math.sqrt(this.calculateVariance(values))
  }

  /**
   * Calculate the entropy of a probability distribution
   * @param probabilities Array of probabilities (should sum to 1)
   * @returns Entropy value
   */
  private calculateEntropy(probabilities: number[]): number {
    if (!probabilities || probabilities.length === 0) return 0
    return -probabilities.reduce((entropy, p) => {
      if (p <= 0) return entropy
      return entropy + p * Math.log2(p)
    }, 0)
  }

  /**
   * Calculate the distance between two points using the Haversine formula
   * @param lat1 Latitude of point 1
   * @param lon1 Longitude of point 1
   * @param lat2 Latitude of point 2
   * @param lon2 Longitude of point 2
   * @returns Distance in kilometers
   */
  private calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
    const R = 6371 // Earth radius in kilometers
    const dLat = this.toRadians(lat2 - lat1)
    const dLon = this.toRadians(lon2 - lon1)
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(this.toRadians(lat1)) * Math.cos(this.toRadians(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2)
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a))
    return R * c
  }

  /**
   * Convert degrees to radians
   * @param degrees Angle in degrees
   * @returns Angle in radians
   */
  private toRadians(degrees: number): number {
    return degrees * (Math.PI / 180)
  }

  /**
   * Extract browser and OS information from user agent string
   * @param userAgent User agent string
   * @returns Browser and OS information
   */
  private extractBrowserInfo(userAgent: string): { browser: string; os: string } {
    try {
      // Simple extraction logic - in a real implementation, use a proper user agent parser
      let browser = "Unknown"
      let os = "Unknown"

      // Extract OS
      if (userAgent.includes("Windows")) {
        os = "Windows"
      } else if (userAgent.includes("Mac OS")) {
        os = "MacOS"
      } else if (userAgent.includes("Linux")) {
        os = "Linux"
      } else if (userAgent.includes("Android")) {
        os = "Android"
      } else if (userAgent.includes("iOS") || userAgent.includes("iPhone") || userAgent.includes("iPad")) {
        os = "iOS"
      }

      // Extract browser
      if (userAgent.includes("Chrome") && !userAgent.includes("Chromium")) {
        browser = "Chrome"
      } else if (userAgent.includes("Firefox")) {
        browser = "Firefox"
      } else if (userAgent.includes("Safari") && !userAgent.includes("Chrome")) {
        browser = "Safari"
      } else if (userAgent.includes("Edge")) {
        browser = "Edge"
      } else if (userAgent.includes("MSIE") || userAgent.includes("Trident")) {
        browser = "Internet Explorer"
      }

      return { browser, os }
    } catch (error) {
      return { browser: "Unknown", os: "Unknown" }
    }
  }

  /**
   * Calculate similarity between two strings (simple implementation)
   * @param str1 First string
   * @param str2 Second string
   * @returns Similarity score (0-1)
   */
  private calculateSimilarity(str1: string, str2: string): number {
    try {
      // Simple Jaccard similarity for demonstration
      const set1 = new Set(str1.split(""))
      const set2 = new Set(str2.split(""))

      const intersection = new Set([...set1].filter((x) => set2.has(x)))
      const union = new Set([...set1, ...set2])

      return intersection.size / union.size
    } catch (error) {
      return 0
    }
  }
