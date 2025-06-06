import type { Request, Response, NextFunction } from 'express';
import { createHash } from 'crypto';
import { logger } from '../../infrastructure/logging/logger';
import { getCurrentCorrelationId } from './correlation-id.middleware';
import { env } from '../../config/environment';

/**
 * Device fingerprint options
 */
interface DeviceFingerprintOptions {
  // Whether to include IP address in fingerprint
  includeIp: boolean;
  // Whether to include user agent in fingerprint
  includeUserAgent: boolean;
  // Whether to include accept-language in fingerprint
  includeAcceptLanguage: boolean;
  // Whether to include screen resolution in fingerprint
  includeScreenResolution: boolean;
  // Whether to include timezone in fingerprint
  includeTimezone: boolean;
  // Whether to include platform in fingerprint
  includePlatform: boolean;
  // Additional headers to include in fingerprint
  additionalHeaders: string[];
  // Salt for fingerprint hashing
  salt: string;
}

/**
 * Default device fingerprint options
 */
const defaultOptions: DeviceFingerprintOptions = {
  includeIp: true,
  includeUserAgent: true,
  includeAcceptLanguage: true,
  includeScreenResolution: true,
  includeTimezone: true,
  includePlatform: true,
  additionalHeaders: [],
  salt: env.get('DEVICE_FINGERPRINT_SALT', 'default-salt') || 'default-salt',
};

/**
 * Create a device fingerprint middleware with custom options
 * @param options Device fingerprint options
 * @returns Device fingerprint middleware
 */
export function createDeviceFingerprintMiddleware(options: Partial<DeviceFingerprintOptions> = {}) {
  // Merge options with defaults
  const mergedOptions: DeviceFingerprintOptions = { ...defaultOptions, ...options };

  return (req: Request, _res: Response, next: NextFunction): void => {
    try {
      const correlationId =
        getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

      // Collect client information
      const components: string[] = [];

      // Add IP address if enabled
      if (mergedOptions.includeIp) {
        components.push(`ip:${req.ip || req.socket.remoteAddress || 'unknown'}`);
      }

      // Add user agent if enabled
      if (mergedOptions.includeUserAgent) {
        components.push(`ua:${req.headers['user-agent'] || 'unknown'}`);
      }

      // Add accept-language if enabled
      if (mergedOptions.includeAcceptLanguage) {
        components.push(`lang:${req.headers['accept-language'] || 'unknown'}`);
      }

      // Add screen resolution if available and enabled
      if (mergedOptions.includeScreenResolution && req.headers['x-screen-resolution']) {
        components.push(`res:${req.headers['x-screen-resolution']}`);
      }

      // Add timezone if available and enabled
      if (mergedOptions.includeTimezone && req.headers['x-timezone-offset']) {
        components.push(`tz:${req.headers['x-timezone-offset']}`);
      }

      // Add platform if available and enabled
      if (mergedOptions.includePlatform && req.headers['x-platform']) {
        components.push(`platform:${req.headers['x-platform']}`);
      }

      // Add additional headers if specified
      for (const header of mergedOptions.additionalHeaders) {
        const value = req.headers[header.toLowerCase()];
        if (value) {
          components.push(`${header}:${value}`);
        }
      }

      // Add salt
      components.push(`salt:${mergedOptions.salt}`);

      // Create fingerprint from client information
      const fingerprint = createFingerprint(components.join('|'));

      // Add fingerprint to request
      req.deviceId = fingerprint;

      // Log fingerprint creation
      logger.debug(`[${correlationId}] Device fingerprint created`, {
        deviceId: fingerprint,
        correlationId,
      });

      next();
    } catch (error) {
      logger.error('Device fingerprint middleware error', {
        error,
        correlationId: getCurrentCorrelationId(),
      });
      // Continue without fingerprint on error
      next();
    }
  };
}

/**
 * Create a fingerprint from client information
 * @param data Client information string
 * @returns Fingerprint hash
 */
function createFingerprint(data: string): string {
  // Create a hash of the data
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Default device fingerprint middleware
 */
export const deviceFingerprint = createDeviceFingerprintMiddleware();

// Note: Express Request interface extensions are now centralized in src/shared/types/express.d.ts
