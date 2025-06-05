import { Injectable } from '@tsed/di';
import { riskConfig } from '../../../config/risk.config';
import { logger } from '../../../infrastructure/logging/logger';
import type { DeviceFingerprintData } from '../risk-types';
import type { UserDeviceRepository } from '../../../data/repositories/user-device.repository';
import type { EventEmitter } from '../../../infrastructure/events/event-emitter';
import { RiskEvent } from '../risk-events';
import * as crypto from 'crypto';

/**
 * Interface for browser information
 */
interface BrowserInfo {
  name: string;
  version: string;
  language: string;
}

/**
 * Interface for OS information
 */
interface OsInfo {
  name: string;
  version: string;
  platform: string;
}

/**
 * Interface for device information
 */
interface DeviceInfo {
  type: string;
  brand: string;
  model: string;
  touch: boolean;
}

/**
 * Interface for raw device fingerprint data
 */
interface RawDeviceFingerprint {
  userAgent?: string;
  screenWidth?: number;
  screenHeight?: number;
  colorDepth?: number;
  connection?: string;
  downlink?: number;
  rtt?: number;
  cookiesEnabled?: boolean;
  localStorage?: boolean;
  sessionStorage?: boolean;
  indexedDb?: boolean;
  canvas?: boolean;
  webgl?: boolean;
  touchSupport?: boolean;
  hasLiedBrowser?: boolean;
  hasLiedOs?: boolean;
  hasLiedResolution?: boolean;
  automationDetected?: boolean;
  emulatorDetected?: boolean;
  [key: string]: any; // Allow for additional properties
}

@Injectable()
export class DeviceFingerprintService {
  // private readonly CACHE_PREFIX = "device-fingerprint:" // Unused
  // private readonly CACHE_TTL = 24 * 60 * 60 // 24 hours - Unused

  constructor(
    // private cacheService: CacheService, // Unused
    private userDeviceRepository: UserDeviceRepository,
    private eventEmitter: EventEmitter
  ) {}

  /**
   * Assess risk based on device fingerprint
   * @param userId User ID (optional)
   * @param fingerprintData Device fingerprint data
   * @returns Risk score (0-100)
   */
  async assessRisk(userId: string | null, fingerprintData: Record<string, any>): Promise<number> {
    try {
      if (!fingerprintData) {
        logger.debug('No fingerprint data provided for device risk assessment');
        return 50; // Moderate risk if no fingerprint data
      }

      // Parse and normalize fingerprint data
      const deviceData = this.parseFingerprint(fingerprintData);
      if (!deviceData) {
        return 50; // Moderate risk if we can't parse the fingerprint
      }

      // Initialize risk score
      let riskScore = 0;
      const riskFactors = riskConfig.deviceFingerprint.riskFactors;

      // Check for device spoofing
      const spoofingScore = this.detectSpoofing(deviceData);
      if (spoofingScore > 0) {
        riskScore = Math.max(riskScore, riskFactors.deviceSpoofing * (spoofingScore / 100));
      }

      // For existing users, check device history
      if (userId) {
        // Check if this is a new device
        const isKnownDevice = await this.isKnownDevice(userId, deviceData.hash);

        if (!isKnownDevice) {
          riskScore = Math.max(riskScore, riskFactors.newDevice);

          // Emit device change event
          this.eventEmitter.emit(RiskEvent.DEVICE_CHANGE_DETECTED, {
            userId,
            deviceHash: deviceData.hash,
            deviceInfo: {
              browser: deviceData.browser.name,
              os: deviceData.os.name,
              deviceType: deviceData.device.type,
            },
            timestamp: new Date(),
          });
        }

        // Check if this device is used by multiple accounts
        const isMultiAccountDevice = await this.isMultiAccountDevice(deviceData.hash, userId);
        if (isMultiAccountDevice) {
          riskScore = Math.max(riskScore, riskFactors.multipleAccounts);
        }
      }

      // Check for suspicious device characteristics
      const suspiciousScore = this.detectSuspiciousDevice(deviceData);
      if (suspiciousScore > 0) {
        riskScore = Math.max(riskScore, riskFactors.suspiciousDevice * (suspiciousScore / 100));
      }

      logger.debug('Device fingerprint risk assessment completed', {
        userId,
        deviceHash: deviceData.hash,
        riskScore,
      });

      return riskScore;
    } catch (error) {
      logger.error('Error assessing device fingerprint risk', { error, userId });
      return 30; // Default to moderate risk on error
    }
  }

  /**
   * Parse and normalize device fingerprint data
   * @param rawData Raw fingerprint data
   * @returns Normalized device fingerprint data
   */
  private parseFingerprint(rawData: RawDeviceFingerprint): DeviceFingerprintData | null {
    try {
      if (!rawData) {
        return null;
      }

      // Extract components based on configuration
      const components: Record<string, any> = {};

      for (const component of riskConfig.deviceFingerprint.components) {
        if (rawData[component] !== undefined) {
          components[component] = rawData[component];
        }
      }

      // If we don't have enough components, return null
      if (Object.keys(components).length < 3) {
        return null;
      }

      // Parse user agent
      const userAgent = rawData['userAgent'] || '';

      // Parse browser info
      const browserInfo = this.parseBrowserInfo(userAgent);

      // Parse OS info
      const osInfo = this.parseOsInfo(userAgent);

      // Parse device info
      const deviceInfo = this.parseDeviceInfo(userAgent, rawData);

      // Parse screen info
      const screenInfo = {
        width: rawData['screenWidth'] || 0,
        height: rawData['screenHeight'] || 0,
        colorDepth: rawData['colorDepth'] || 0,
      };

      // Parse network info
      const networkInfo = {
        connection: rawData['connection'] || 'unknown',
        downlink: rawData['downlink'] || 0,
        rtt: rawData['rtt'] || 0,
      };

      // Parse features
      const features: Record<string, boolean> = {
        cookies: rawData['cookiesEnabled'] === true,
        localStorage: rawData['localStorage'] === true,
        sessionStorage: rawData['sessionStorage'] === true,
        indexedDb: rawData['indexedDb'] === true,
        canvas: rawData['canvas'] === true,
        webgl: rawData['webgl'] === true,
      };

      // Detect anomalies
      const anomalies = this.detectAnomalies(rawData, browserInfo, osInfo, deviceInfo);

      // Generate hash
      const hash = this.generateFingerprintHash(components);

      return {
        hash,
        components,
        userAgent,
        browser: browserInfo,
        os: osInfo,
        device: deviceInfo,
        screen: screenInfo,
        network: networkInfo,
        features,
        anomalies,
      };
    } catch (error) {
      logger.error('Error parsing device fingerprint', { error });
      return null;
    }
  }

  /**
   * Parse browser information from user agent
   * @param userAgent User agent string
   * @returns Browser information
   */
  private parseBrowserInfo(userAgent: string): { name: string; version: string; language: string } {
    try {
      if (!userAgent) {
        return { name: 'unknown', version: 'unknown', language: 'unknown' };
      }

      let name = 'unknown';
      let version = 'unknown';

      // Extract browser name and version
      if (userAgent.includes('Chrome')) {
        name = 'Chrome';
        const match = userAgent.match(/Chrome\/(\d+\.\d+)/) ?? [];
        version = match[1] ?? 'unknown';
      } else if (userAgent.includes('Firefox')) {
        name = 'Firefox';
        const match = userAgent.match(/Firefox\/(\d+\.\d+)/) ?? [];
        version = match[1] ?? 'unknown';
      } else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) {
        name = 'Safari';
        const match = userAgent.match(/Version\/(\d+\.\d+)/) ?? [];
        version = match[1] ?? 'unknown';
      } else if (userAgent.includes('Edge') || userAgent.includes('Edg/')) {
        name = 'Edge';
        const match =
          userAgent.match(/Edge\/(\d+\.\d+)/) || userAgent.match(/Edg\/(\d+\.\d+)/) || [];
        version = match[1] ?? 'unknown';
      } else if (userAgent.includes('MSIE') || userAgent.includes('Trident/')) {
        name = 'Internet Explorer';
        const match = userAgent.match(/MSIE (\d+\.\d+)/) || userAgent.match(/rv:(\d+\.\d+)/) || [];
        version = match[1] ?? 'unknown';
      } else if (userAgent.includes('Opera') || userAgent.includes('OPR/')) {
        name = 'Opera';
        const match =
          userAgent.match(/Opera\/(\d+\.\d+)/) || userAgent.match(/OPR\/(\d+\.\d+)/) || [];
        version = match[1] ?? 'unknown';
      }

      return {
        name,
        version,
        language: 'en-US', // Default, would be extracted from actual data
      };
    } catch (error) {
      logger.error('Error parsing browser info', { error, userAgent });
      return { name: 'unknown', version: 'unknown', language: 'unknown' };
    }
  }

  /**
   * Parse OS information from user agent
   * @param userAgent User agent string
   * @returns OS information
   */
  private parseOsInfo(userAgent: string): { name: string; version: string; platform: string } {
    try {
      if (!userAgent) {
        return { name: 'unknown', version: 'unknown', platform: 'unknown' };
      }

      let name = 'unknown';
      let version = 'unknown';
      let platform = 'unknown';

      // Extract OS name and version
      if (userAgent.includes('Windows')) {
        name = 'Windows';
        platform = 'desktop';

        if (userAgent.includes('Windows NT 10.0')) {
          version = '10';
        } else if (userAgent.includes('Windows NT 6.3')) {
          version = '8.1';
        } else if (userAgent.includes('Windows NT 6.2')) {
          version = '8';
        } else if (userAgent.includes('Windows NT 6.1')) {
          version = '7';
        } else if (userAgent.includes('Windows NT 6.0')) {
          version = 'Vista';
        } else if (userAgent.includes('Windows NT 5.1')) {
          version = 'XP';
        }
      } else if (userAgent.includes('Macintosh') || userAgent.includes('Mac OS X')) {
        name = 'macOS';
        platform = 'desktop';

        const match = userAgent.match(/Mac OS X (\d+[._]\d+)/) ?? [];
        if (match[1]) {
          version = match[1].replace('_', '.');
        }
      } else if (userAgent.includes('Linux')) {
        name = 'Linux';
        platform = 'desktop';

        if (userAgent.includes('Ubuntu')) {
          name = 'Ubuntu';
        } else if (userAgent.includes('Fedora')) {
          name = 'Fedora';
        }
      } else if (userAgent.includes('Android')) {
        name = 'Android';
        platform = 'mobile';

        const match = userAgent.match(/Android (\d+\.\d+)/) ?? [];
        version = match[1] ?? 'unknown';
      } else if (
        userAgent.includes('iPhone') ||
        userAgent.includes('iPad') ||
        userAgent.includes('iPod')
      ) {
        name = 'iOS';
        platform = userAgent.includes('iPad') ? 'tablet' : 'mobile';

        const match = userAgent.match(/OS (\d+[._]\d+)/) ?? [];
        if (match[1]) {
          version = match[1].replace('_', '.');
        }
      }

      return { name, version, platform };
    } catch (error) {
      logger.error('Error parsing OS info', { error, userAgent });
      return { name: 'unknown', version: 'unknown', platform: 'unknown' };
    }
  }

  /**
   * Parse device information from user agent and fingerprint data
   * @param userAgent User agent string
   * @param fingerprintData Fingerprint data
   * @returns Device information
   */
  private parseDeviceInfo(
    userAgent: string,
    fingerprintData: RawDeviceFingerprint
  ): { type: string; brand: string; model: string; touch: boolean } {
    try {
      if (!userAgent) {
        return { type: 'unknown', brand: 'unknown', model: 'unknown', touch: false };
      }

      let type = 'desktop';
      let brand = 'unknown';
      let model = 'unknown';
      let touch = false;

      // Determine device type
      if (
        userAgent.includes('iPhone') ||
        (userAgent.includes('Android') && !userAgent.includes('Mobile'))
      ) {
        type = 'mobile';
      } else if (
        userAgent.includes('iPad') ||
        (userAgent.includes('Android') && !userAgent.includes('Mobile'))
      ) {
        type = 'tablet';
      }

      // Determine brand and model
      if (userAgent.includes('iPhone')) {
        brand = 'Apple';
        model = 'iPhone';
      } else if (userAgent.includes('iPad')) {
        brand = 'Apple';
        model = 'iPad';
      } else if (userAgent.includes('Macintosh')) {
        brand = 'Apple';
        model = 'Mac';
      } else if (userAgent.includes('Android')) {
        brand = 'Android';

        // Try to extract model from user agent
        const modelMatch = userAgent.match(/Android.*?; (.*?)(?:Build|[;)])/i);
        if (modelMatch) {
          model = modelMatch[1].trim();

          // Try to extract brand from model
          const brandMatch = model.match(
            /^(Samsung|LG|Huawei|Xiaomi|OnePlus|Google|Motorola|Sony|Nokia|HTC)/i
          );
          if (bruandMatch) {
            brand = brandMatch[1];
          }
        }
      } else if (userAgent.includes('Windows')) {
        brand = 'Microsoft';
        model = 'PC';
      } else if (userAgent.includes('Linux')) {
        brand = 'Linux';
        model = 'PC';
      }

      // Determine touch capability
      if (fingerprintData['touchSupport']) {
        touch = true;
      } else if (type === 'mobile' || type === 'tablet') {
        touch = true;
      }

      return { type, brand, model, touch };
    } catch (error) {
      logger.error('Error parsing device info', { error, userAgent });
      return { type: 'unknown', brand: 'unknown', model: 'unknown', touch: false };
    }
  }

  /**
   * Detect anomalies in device fingerprint
   * @param data Fingerprint data
   * @param browser Browser info
   * @param os OS info
   * @param device Device info
   * @returns Array of anomaly descriptions
   */
  private detectAnomalies(
    data: RawDeviceFingerprint,
    browser: { name: string; version: string; language: string },
    os: { name: string; version: string; platform: string },
    device: { type: string; brand: string; model: string; touch: boolean }
  ): string[] {
    const anomalies: string[] = [];

    try {
      // Check for inconsistencies between user agent and other data
      if (data['hasLiedBrowser']) {
        anomalies.push('browser_inconsistency');
      }

      if (data['hasLiedOs']) {
        anomalies.push('os_inconsistency');
      }

      if (data['hasLiedResolution']) {
        anomalies.push('resolution_inconsistency');
      }

      // Check for touch support inconsistency
      if (
        (device?.type === 'mobile' || device?.type === 'tablet') &&
        data['touchSupport'] === false
      ) {
        anomalies.push('touch_support_inconsistency');
      }

      // Check for headless browser indicators
      if (!data['localStorage'] || !data['sessionStorage'] || !data['canvas'] || !data['webgl']) {
        anomalies.push('headless_browser_indicators');
      }

      // Check for automation tools
      if (data['automationDetected']) {
        anomalies.push('automation_detected');
      }

      // Check for emulator/simulator
      if (data['emulatorDetected']) {
        anomalies.push('emulator_detected');
      }

      return anomalies;
    } catch (error) {
      logger.error('Error detecting anomalies', { error });
      return anomalies;
    }
  }

  /**
   * Generate a hash from device fingerprint components
   * @param components Fingerprint components
   * @returns Hash string
   */
  private generateFingerprintHash(components: Record<string, any>): string {
    try {
      if (!components || Object.keys(components).length === 0) {
        return crypto.randomBytes(16).toString('hex'); // Fallback to random hash
      }

      // Create a stable JSON representation of components
      const stableJson = JSON.stringify(components, Object.keys(components).sort());

      // Generate SHA-256 hash
      return crypto.createHash('sha256').update(stableJson).digest('hex');
    } catch (error) {
      logger.error('Error generating fingerprint hash', { error });
      return crypto.randomBytes(16).toString('hex'); // Fallback to random hash
    }
  }

  /**
   * Detect device spoofing
   * @param deviceData Device fingerprint data
   * @returns Spoofing score (0-100)
   */
  private detectSpoofing(deviceData: DeviceFingerprintData): number {
    let spoofingScore = 0;

    try {
      if (!deviceData) {
        return 0;
      }

      // Check for known spoofing indicators
      if (deviceData.anomalies?.length > 0) {
        // Each anomaly adds to the spoofing score
        spoofingScore += deviceData.anomalies.length * 20;
      }

      // Check for inconsistencies in browser features
      const { browser, os, device, features } = deviceData;

      // Browser-specific inconsistencies
      if (browser?.name === 'Chrome' && !features?.['canvas']) {
        spoofingScore += 30;
      }

      if (browser?.name === 'Safari' && features?.['webgl'] && !features?.['canvas']) {
        spoofingScore += 30;
      }

      // OS-specific inconsistencies
      if (os?.name === 'iOS' && browser?.name !== 'Safari' && browser?.name !== 'Chrome') {
        spoofingScore += 40;
      }

      // Device-specific inconsistencies
      if (device?.type === 'mobile' && !device?.touch) {
        spoofingScore += 30;
      }

      // Cap the score at 100
      return Math.min(100, spoofingScore);
    } catch (error) {
      logger.error('Error detecting device spoofing', { error });
      return 0;
    }
  }

  /**
   * Detect suspicious device characteristics
   * @param deviceData Device fingerprint data
   * @returns Suspicious score (0-100)
   */
  private detectSuspiciousDevice(deviceData: DeviceFingerprintData): number {
    let suspiciousScore = 0;

    try {
      if (!deviceData) {
        return 0;
      }

      // Check for suspicious browser/OS combinations
      const { browser, os, device, features } = deviceData;

      // Outdated browsers are suspicious
      if (
        browser?.name === 'Internet Explorer' ||
        (browser?.name === 'Chrome' && Number.parseInt(browser.version || '0') < 80) ||
        (browser?.name === 'Firefox' && Number.parseInt(browser.version || '0') < 70) ||
        (browser?.name === 'Safari' && Number.parseInt(browser.version || '0') < 13)
      ) {
        suspiciousScore += 30;
      }

      // Unusual OS versions
      if (
        (os?.name === 'Windows' && ['XP', 'Vista', '7'].includes(os.version || '')) ||
        (os?.name === 'Android' && Number.parseInt(os.version || '0') < 8) ||
        (os?.name === 'iOS' && Number.parseInt(os.version || '0') < 12)
      ) {
        suspiciousScore += 20;
      }

      // Unusual feature combinations
      if (
        features &&
        !features['cookies'] &&
        !features['localStorage'] &&
        !features['sessionStorage']
      ) {
        suspiciousScore += 40;
      }

      // Known bot/crawler patterns
      if (
        deviceData.userAgent &&
        (deviceData.userAgent.includes('bot') ||
          deviceData.userAgent.includes('crawler') ||
          deviceData.userAgent.includes('spider'))
      ) {
        suspiciousScore += 80;
      }

      // Cap the score at 100
      return Math.min(100, suspiciousScore);
    } catch (error) {
      logger.error('Error detecting suspicious device', { error });
      return 0;
    }
  }

  /**
   * Check if this is a known device for the user
   * @param userId User ID
   * @param deviceHash Device hash
   * @returns True if this is a known device
   */
  private async isKnownDevice(userId: string, deviceHash: string): Promise<boolean> {
    try {
      if (!userId || !deviceHash) {
        return false;
      }

      const device = await this.userDeviceRepository.findByUserIdAndHash(userId, deviceHash);
      return device !== null && device !== undefined;
    } catch (error) {
      logger.error('Error checking if device is known', { error, userId, deviceHash });
      return false;
    }
  }

  /**
   * Check if this device is used by multiple accounts
   * @param deviceHash Device hash
   * @param currentUserId Current user ID
   * @returns True if this device is used by multiple accounts
   */
  private async isMultiAccountDevice(deviceHash: string, currentUserId: string): Promise<boolean> {
    try {
      if (!deviceHash || !currentUserId) {
        return false;
      }

      const userCount = await this.userDeviceRepository.countUsersByDeviceHash(deviceHash);

      // If this device is associated with more than one user (including the current user)
      return userCount > 1;
    } catch (error) {
      logger.error('Error checking if device is used by multiple accounts', {
        error,
        deviceHash,
        currentUserId,
      });
      return false;
    }
  }

  /**
   * Register a new device for a user
   * @param userId User ID
   * @param deviceData Device fingerprint data
   * @returns Device ID
   */
  async registerDevice(userId: string, deviceData: RawDeviceFingerprint): Promise<string> {
    try {
      if (!userId || !deviceData) {
        throw new Error('Invalid user ID or device data');
      }

      // Parse and normalize fingerprint data
      const parsedData = this.parseFingerprint(deviceData);
      if (!parsedData) {
        throw new Error('Invalid device fingerprint data');
      }

      // Check if device already exists for this user
      const existingDevice = await this.userDeviceRepository.findByUserIdAndHash(
        userId,
        parsedData.hash
      );

      if (existingDevice) {
        // Update last seen time
        await this.userDeviceRepository.updateLastSeen(existingDevice.id);
        return existingDevice.id;
      }

      // Create new device
      const device = await this.userDeviceRepository.create({
        userId,
        deviceHash: parsedData.hash,
        name: this.generateDeviceName(parsedData),
        browser: parsedData.browser.name,
        os: parsedData.os.name,
        deviceType: parsedData.device.type,
        isTrusted: false, // New devices are not trusted by default
        metadata: {
          browser: parsedData.browser,
          os: parsedData.os,
          device: parsedData.device,
          screen: parsedData.screen,
          features: parsedData.features,
        },
      });

      return device.id;
    } catch (error) {
      logger.error('Error registering device', { error, userId });
      throw error;
    }
  }

  /**
   * Generate a user-friendly device name
   * @param deviceData Device fingerprint data
   * @returns Device name
   */
  private generateDeviceName(deviceData: DeviceFingerprintData): string {
    try {
      if (!deviceData) {
        return 'Unknown Device';
      }

      const { browser, os, device } = deviceData;
      let name = '';

      // Add device brand/model if available
      if (device?.brand !== 'unknown' && device?.model !== 'unknown') {
        name += `${device.brand} ${device.model}`;
      } else if (device?.type !== 'unknown') {
        name += device.type.charAt(0).toUpperCase() + device.type.slice(1);
      } else {
        name += 'Device';
      }

      // Add OS
      if (os?.name !== 'unknown') {
        name += ` (${os.name}`;

        if (os.version !== 'unknown') {
          name += ` ${os.version}`;
        }

        name += ')';
      }

      // Add browser
      if (browser?.name !== 'unknown') {
        name += ` - ${browser.name}`;
      }

      return name;
    } catch (error) {
      logger.error('Error generating device name', { error });
      return 'Unknown Device';
    }
  }

  /**
   * Trust a device for a user
   * @param userId User ID
   * @param deviceId Device ID
   * @returns Success status
   */
  async trustDevice(userId: string, deviceId: string): Promise<boolean> {
    try {
      if (!userId || !deviceId) {
        return false;
      }

      // Check if device belongs to user
      const device = await this.userDeviceRepository.findById(deviceId);

      if (!device || device.userId !== userId) {
        return false;
      }

      // Update device trust status
      await this.userDeviceRepository.update(deviceId, {
        isTrusted: true,
        trustExpiresAt: new Date(
          Date.now() + riskConfig.deviceFingerprint.trustDeviceDuration * 1000
        ),
      });

      return true;
    } catch (error) {
      logger.error('Error trusting device', { error, userId, deviceId });
      return false;
    }
  }
}
