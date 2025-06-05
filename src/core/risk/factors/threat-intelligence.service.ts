import { Injectable } from '@tsed/di';
import { riskConfig } from '../../../config/risk.config';
import { logger } from '../../../infrastructure/logging/logger';
import type { CacheService } from '../../cache/cache.service';
import type { HttpClient } from '../../../infrastructure/http/http-client';
import type { UserRepository } from '../../../data/repositories/user.repository';
import type { EventEmitter } from '../../../infrastructure/events/event-emitter';
import { RiskEvent } from '../risk-events';

/**
 * Threat intelligence service for risk assessment
 * Checks for known threats, compromised credentials, and attack patterns
 */
@Injectable()
export class ThreatIntelligenceService {
  private readonly CACHE_PREFIX = 'threat-intel:';
  private readonly CACHE_TTL = riskConfig.threatIntelligence.cacheTime;

  constructor(
    private cacheService: CacheService,
    private httpClient: HttpClient,
    private userRepository: UserRepository,
    private eventEmitter: EventEmitter
  ) {}

  /**
   * Assess risk based on threat intelligence
   * @param userId User ID (optional)
   * @param context Authentication context
   * @returns Risk score (0-100)
   */
  async assessRisk(userId: string | null, context: Record<string, any>): Promise<number> {
    try {
      logger.debug('Starting threat intelligence assessment', { userId });

      // Initialize risk score
      let riskScore = 0;
      const riskFactors = riskConfig.threatIntelligence.riskFactors;

      // Check for known threat actor
      const isThreatActor = await this.checkKnownThreatActor(
        context.ipAddress,
        context.deviceFingerprint
      );
      if (isThreatActor) {
        riskScore = Math.max(riskScore, riskFactors.knownThreatActor);

        // Emit threat actor event
        this.eventEmitter.emit(RiskEvent.THREAT_ACTOR_DETECTED, {
          userId,
          ipAddress: context.ipAddress,
          deviceFingerprint: context.deviceFingerprint,
          timestamp: new Date(),
        });
      }

      // Check for compromised credentials (only if userId is provided)
      if (userId) {
        const hasCompromisedCredentials = await this.checkCompromisedCredentials(userId);
        if (hasCompromisedCredentials) {
          riskScore = Math.max(riskScore, riskFactors.compromisedCredentials);

          // Emit compromised credentials event
          this.eventEmitter.emit(RiskEvent.COMPROMISED_CREDENTIALS_DETECTED, {
            userId,
            timestamp: new Date(),
          });
        }
      }

      // Check for botnet activity
      const isInBotnet = await this.checkBotnetActivity(
        context.ipAddress,
        context.deviceFingerprint
      );
      if (isInBotnet) {
        riskScore = Math.max(riskScore, riskFactors.botnetActivity);

        // Emit botnet activity event
        this.eventEmitter.emit(RiskEvent.BOTNET_ACTIVITY_DETECTED, {
          userId,
          ipAddress: context.ipAddress,
          deviceFingerprint: context.deviceFingerprint,
          timestamp: new Date(),
        });
      }

      // Check for phishing indicators
      const phishingIndicators = this.checkPhishingIndicators(context);
      if (phishingIndicators) {
        riskScore = Math.max(riskScore, riskFactors.phishingAttempt);

        // Emit phishing attempt event
        this.eventEmitter.emit(RiskEvent.PHISHING_ATTEMPT_DETECTED, {
          userId,
          indicators: phishingIndicators,
          context: this.sanitizeContext(context),
          timestamp: new Date(),
        });
      }

      // Check for attack patterns
      const attackPattern = await this.checkAttackPatterns(context);
      if (attackPattern) {
        riskScore = Math.max(riskScore, riskFactors.attackPattern);

        // Emit attack pattern event
        this.eventEmitter.emit(RiskEvent.ATTACK_PATTERN_DETECTED, {
          userId,
          pattern: attackPattern,
          context: this.sanitizeContext(context),
          timestamp: new Date(),
        });
      }

      logger.debug('Threat intelligence assessment completed', { userId, riskScore });

      return riskScore;
    } catch (error) {
      logger.error('Error in threat intelligence assessment', { error, userId });
      return 0; // Default to no risk on error
    }
  }

  /**
   * Check if IP or device is associated with known threat actors
   * @param ipAddress IP address
   * @param deviceFingerprint Device fingerprint
   * @returns True if associated with known threat actors
   */
  private async checkKnownThreatActor(
    ipAddress?: string,
    deviceFingerprint?: string
  ): Promise<boolean> {
    try {
      if (!ipAddress && !deviceFingerprint) {
        return false;
      }

      // Check cache first
      const cacheKey = `${this.CACHE_PREFIX}threat-actor:${ipAddress || ''}:${deviceFingerprint || ''}`;
      const cachedResult = await this.cacheService.get<boolean>(cacheKey);

      if (cachedResult !== null) {
        return cachedResult;
      }

      // In a real implementation, this would check threat intelligence feeds
      // For now, we'll use a simple simulation

      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 100));

      // For demonstration purposes, consider some IP ranges as threat actors
      let isThreatActor = false;

      if (ipAddress) {
        const ipParts = ipAddress.split('.');
        if (ipParts.length === 4) {
          const firstOctet = Number.parseInt(ipParts[0], 10);
          const secondOctet = Number.parseInt(ipParts[1], 10);

          // Example: Consider some ranges as threat actors
          if (
            (firstOctet === 185 && secondOctet >= 180 && secondOctet <= 190) ||
            (firstOctet === 194 && secondOctet >= 50 && secondOctet <= 60)
          ) {
            isThreatActor = true;
          }
        }
      }

      // Cache the result
      await this.cacheService.set(cacheKey, isThreatActor, this.CACHE_TTL);

      return isThreatActor;
    } catch (error) {
      logger.error('Error checking known threat actor', { error, ipAddress });
      return false;
    }
  }

  /**
   * Check if user's credentials have been compromised
   * @param userId User ID
   * @returns True if credentials are compromised
   */
  private async checkCompromisedCredentials(userId: string): Promise<boolean> {
    try {
      // Check cache first
      const cacheKey = `${this.CACHE_PREFIX}compromised-credentials:${userId}`;
      const cachedResult = await this.cacheService.get<boolean>(cacheKey);

      if (cachedResult !== null) {
        return cachedResult;
      }

      // Get user's email
      const user = await this.userRepository.findById(userId);
      if (!user || !user.email) {
        return false;
      }

      // In a real implementation, this would check breach databases like HaveIBeenPwned
      // For now, we'll use a simple simulation

      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 150));

      // For demonstration purposes, consider some email patterns as compromised
      const isCompromised = user.email.includes('test') || user.email.includes('demo');

      // Cache the result
      await this.cacheService.set(cacheKey, isCompromised, this.CACHE_TTL);

      return isCompromised;
    } catch (error) {
      logger.error('Error checking compromised credentials', { error, userId });
      return false;
    }
  }

  /**
   * Check if IP or device is part of a botnet
   * @param ipAddress IP address
   * @param deviceFingerprint Device fingerprint
   * @returns True if part of a botnet
   */
  private async checkBotnetActivity(
    ipAddress?: string,
    deviceFingerprint?: string
  ): Promise<boolean> {
    try {
      if (!ipAddress && !deviceFingerprint) {
        return false;
      }

      // Check cache first
      const cacheKey = `${this.CACHE_PREFIX}botnet:${ipAddress || ''}:${deviceFingerprint || ''}`;
      const cachedResult = await this.cacheService.get<boolean>(cacheKey);

      if (cachedResult !== null) {
        return cachedResult;
      }

      // In a real implementation, this would check botnet tracking services
      // For now, we'll use a simple simulation

      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 120));

      // For demonstration purposes, consider some IP ranges as part of botnets
      let isInBotnet = false;

      if (ipAddress) {
        const ipParts = ipAddress.split('.');
        if (ipParts.length === 4) {
          const firstOctet = Number.parseInt(ipParts[0], 10);
          const secondOctet = Number.parseInt(ipParts[1], 10);

          // Example: Consider some ranges as part of botnets
          if (
            (firstOctet === 91 && secondOctet >= 200 && secondOctet <= 220) ||
            (firstOctet === 104 && secondOctet >= 130 && secondOctet <= 140)
          ) {
            isInBotnet = true;
          }
        }
      }

      // Cache the result
      await this.cacheService.set(cacheKey, isInBotnet, this.CACHE_TTL);

      return isInBotnet;
    } catch (error) {
      logger.error('Error checking botnet activity', { error, ipAddress });
      return false;
    }
  }

  /**
   * Check for phishing indicators in the authentication context
   * @param context Authentication context
   * @returns Object with phishing indicators or false if none
   */
  private checkPhishingIndicators(context: Record<string, any>): Record<string, boolean> | false {
    try {
      if (!context) {
        return false;
      }

      const indicators: Record<string, boolean> = {};
      let hasIndicators = false;

      // Check for suspicious referrer
      if (context.referrer) {
        const suspiciousReferrers = [
          'login-secure',
          'account-verify',
          'security-check',
          'password-reset',
          'signin-help',
        ];

        for (const term of suspiciousReferrers) {
          if (context.referrer.includes(term)) {
            indicators.suspiciousReferrer = true;
            hasIndicators = true;
            break;
          }
        }
      }

      // Check for suspicious user agent
      if (context.userAgent) {
        const suspiciousUserAgents = [
          'PhishingBrowser',
          'DataCollector',
          'WebScraper',
          'HeadlessChrome',
          'PhantomJS',
        ];

        for (const term of suspiciousUserAgents) {
          if (context.userAgent.includes(term)) {
            indicators.suspiciousUserAgent = true;
            hasIndicators = true;
            break;
          }
        }
      }

      // Check for automated form submission
      if (context.formSubmissionTime !== undefined && context.formSubmissionTime < 1000) {
        // Form submitted in less than 1 second
        indicators.rapidFormSubmission = true;
        hasIndicators = true;
      }

      // Check for suspicious headers
      if (context.headers) {
        if (!context.headers['accept-language'] || context.headers['accept-language'] === '*') {
          indicators.suspiciousHeaders = true;
          hasIndicators = true;
        }
      }

      return hasIndicators ? indicators : false;
    } catch (error) {
      logger.error('Error checking phishing indicators', { error });
      return false;
    }
  }

  /**
   * Check for attack patterns in the authentication context
   * @param context Authentication context
   * @returns Attack pattern name or null if none detected
   */
  private async checkAttackPatterns(context: Record<string, any>): Promise<string | null> {
    try {
      if (!context) {
        return null;
      }

      // Check for credential stuffing
      if (
        context.failedAttempts &&
        context.failedAttempts > 5 &&
        context.uniqueUsernames &&
        context.uniqueUsernames > 3
      ) {
        return 'credential_stuffing';
      }

      // Check for brute force
      if (
        context.failedAttempts &&
        context.failedAttempts > 10 &&
        context.timeWindow &&
        context.timeWindow < 300
      ) {
        return 'brute_force';
      }

      // Check for password spraying
      if (
        context.failedAttempts &&
        context.failedAttempts > 5 &&
        context.uniqueUsernames &&
        context.uniqueUsernames > 5 &&
        context.uniquePasswords &&
        context.uniquePasswords < 3
      ) {
        return 'password_spraying';
      }

      // Check for account enumeration
      if (
        context.failedAttempts &&
        context.failedAttempts > 10 &&
        context.uniqueUsernames &&
        context.uniqueUsernames > 10 &&
        context.timeWindow &&
        context.timeWindow < 600
      ) {
        return 'account_enumeration';
      }

      // Check for session hijacking
      if (
        context.sessionId &&
        context.originalIp &&
        context.ipAddress &&
        context.originalIp !== context.ipAddress
      ) {
        return 'session_hijacking';
      }

      return null;
    } catch (error) {
      logger.error('Error checking attack patterns', { error });
      return null;
    }
  }

  /**
   * Sanitize context for logging (remove sensitive data)
   * @param context Authentication context
   * @returns Sanitized context
   */
  private sanitizeContext(context: Record<string, any>): Record<string, any> {
    if (!context) {
      return {};
    }

    const sanitized = { ...context };

    // Remove sensitive fields
    delete sanitized.password;
    delete sanitized.token;
    delete sanitized.accessToken;
    delete sanitized.refreshToken;

    // Truncate potentially large fields
    if (sanitized.deviceFingerprint) {
      sanitized.deviceFingerprint = 'present';
    }

    return sanitized;
  }
}
