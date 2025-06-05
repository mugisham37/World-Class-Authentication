import { Injectable } from '@tsed/di';
import { riskConfig } from '../../../config/risk.config';
import { logger } from '../../../infrastructure/logging/logger';
import type { CacheService } from '../../cache/cache.service';

@Injectable()
export class IpReputationService {
  private readonly CACHE_PREFIX = 'ip-reputation:';
  private readonly CACHE_TTL = riskConfig.ipReputation.cacheTime;

  constructor(
    private cacheService: CacheService
    // TODO: Will be used for real API calls to IP reputation services
    // private httpClient: HttpClient,
  ) {}

  /**
   * Assess risk for an IP address
   * @param ipAddress IP address
   * @returns Risk score (0-100)
   */
  async assessRisk(ipAddress: string): Promise<number> {
    try {
      if (!ipAddress) {
        logger.debug('No IP address provided for risk assessment');
        return 0;
      }

      // Check cache first
      const cacheKey = `${this.CACHE_PREFIX}${ipAddress}`;
      const cachedScore = await this.cacheService.get<number>(cacheKey);

      if (cachedScore !== null) {
        logger.debug('Using cached IP reputation score', { ipAddress, score: cachedScore });
        return cachedScore;
      }

      // Calculate score based on configured providers
      let score = 0;
      const providers = riskConfig.ipReputation.providers;

      // Use local database if configured
      if (providers.includes('local')) {
        score = await this.checkLocalDatabase(ipAddress);
      }

      // Use external providers if configured and local score is low
      if (score < riskConfig.ipReputation.thresholds.suspicious) {
        if (providers.includes('abuseipdb')) {
          score = Math.max(score, await this.checkAbuseIpDb(ipAddress));
        }

        if (
          providers.includes('ipqualityscore') &&
          score < riskConfig.ipReputation.thresholds.suspicious
        ) {
          score = Math.max(score, await this.checkIpQualityScore(ipAddress));
        }

        if (providers.includes('ipinfo') && score < riskConfig.ipReputation.thresholds.suspicious) {
          score = Math.max(score, await this.checkIpInfo(ipAddress));
        }
      }

      // Cache the result
      await this.cacheService.set(cacheKey, score, this.CACHE_TTL);

      logger.debug('IP reputation assessment completed', { ipAddress, score });
      return score;
    } catch (error) {
      this.logError('Error assessing IP reputation', error, ipAddress);
      return 0; // Default to no risk on error
    }
  }

  /**
   * Check local IP reputation database
   * @param ipAddress IP address
   * @returns Risk score (0-100)
   */
  private async checkLocalDatabase(ipAddress: string): Promise<number> {
    try {
      // In a real implementation, this would query a local database of known bad IPs
      // For now, we'll use a simple implementation that checks for private IPs

      // Check if it's a private IP (low risk)
      if (
        ipAddress.startsWith('10.') ||
        ipAddress.startsWith('192.168.') ||
        ipAddress.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)
      ) {
        return 0;
      }

      // Check if it's a localhost (low risk)
      if (ipAddress === '127.0.0.1' || ipAddress === '::1') {
        return 0;
      }

      // Check if it's a known testing IP (low risk)
      if (ipAddress === '0.0.0.0' || ipAddress === '255.255.255.255') {
        return 0;
      }

      // For demonstration purposes, assign random scores to some IP ranges
      // In a real implementation, this would be based on actual threat intelligence
      const ipParts = ipAddress.split('.');
      if (ipParts.length === 4) {
        const firstOctet = Number.parseInt(ipParts[0] ?? '0', 10);

        // Example: Consider some ranges higher risk
        if (firstOctet >= 185 && firstOctet <= 195) {
          return 60; // Higher risk range
        }
      }

      // Default score for unknown IPs
      return 10;
    } catch (error) {
      this.logError('Error checking local IP database', error, ipAddress);
      return 0;
    }
  }

  /**
   * Check AbuseIPDB for IP reputation
   * @param ipAddress IP address
   * @returns Risk score (0-100)
   */
  private async checkAbuseIpDb(ipAddress: string): Promise<number> {
    try {
      // In a real implementation, this would call the AbuseIPDB API
      // For now, we'll simulate a response

      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 100));

      // For demonstration purposes, return a score based on the IP
      // In a real implementation, this would be based on the API response
      const ipParts = ipAddress.split('.');
      if (ipParts.length === 4) {
        const lastOctet = Number.parseInt(ipParts[3] ?? '0', 10);

        // Example: Higher score for IPs ending in certain ranges
        if (lastOctet >= 200) {
          return 75;
        } else if (lastOctet >= 150) {
          return 50;
        } else if (lastOctet >= 100) {
          return 25;
        }
      }

      return 0;
    } catch (error) {
      this.logError('Error checking AbuseIPDB', error, ipAddress);
      return 0;
    }
  }

  /**
   * Check IPQualityScore for IP reputation
   * @param ipAddress IP address
   * @returns Risk score (0-100)
   */
  private async checkIpQualityScore(ipAddress: string): Promise<number> {
    try {
      // In a real implementation, this would call the IPQualityScore API
      // For now, we'll simulate a response

      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 150));

      // For demonstration purposes, return a score based on the IP
      // In a real implementation, this would be based on the API response
      const ipParts = ipAddress.split('.');
      if (ipParts.length === 4) {
        const secondOctet = Number.parseInt(ipParts[1] ?? '0', 10);

        // Example: Higher score for IPs with certain second octet
        if (secondOctet >= 200) {
          return 80;
        } else if (secondOctet >= 150) {
          return 60;
        } else if (secondOctet >= 100) {
          return 30;
        }
      }

      return 0;
    } catch (error) {
      this.logError('Error checking IPQualityScore', error, ipAddress);
      return 0;
    }
  }

  /**
   * Check IPInfo for IP reputation
   * @param ipAddress IP address
   * @returns Risk score (0-100)
   */
  private async checkIpInfo(ipAddress: string): Promise<number> {
    try {
      // In a real implementation, this would call the IPInfo API
      // For now, we'll simulate a response

      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 120));

      // For demonstration purposes, return a score based on the IP
      // In a real implementation, this would be based on the API response
      const ipParts = ipAddress.split('.');
      if (ipParts.length === 4) {
        const firstOctet = Number.parseInt(ipParts[0] ?? '0', 10);

        // Example: Higher score for certain IP ranges
        if (firstOctet >= 190 && firstOctet <= 200) {
          return 70;
        } else if (firstOctet >= 180 && firstOctet <= 190) {
          return 40;
        }
      }

      return 0;
    } catch (error) {
      this.logError('Error checking IPInfo', error, ipAddress);
      return 0;
    }
  }

  /**
   * Helper method to safely log errors with IP addresses
   * @param message Error message
   * @param error Error object
   * @param ipAddress IP address (may be undefined in catch blocks)
   */
  private logError(message: string, error: unknown, ipAddress: string): void {
    logger.error(message, { error, ipAddress: ipAddress || 'unknown' });
  }
}
