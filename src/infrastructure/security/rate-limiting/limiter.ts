import { Request, Response, NextFunction } from 'express';
import { createClient, RedisClientType } from 'redis';
import { logger } from '../../logging/logger';
import { securityConfig } from '../../../config/security-config';

/**
 * Rate Limiter Factory
 * Creates rate limiters with different configurations
 */
export class RateLimiterFactory {
  private static redisClient: RedisClientType | null = null;
  private static isRedisConnected = false;
  private static localCache: Map<string, { count: number; resetTime: number }> = new Map();

  /**
   * Initialize Redis client
   */
  static async initializeRedis(): Promise<void> {
    try {
      if (securityConfig.rateLimit.useRedis) {
        this.redisClient = createClient({
          url: `redis://${process.env['REDIS_HOST'] || 'localhost'}:${process.env['REDIS_PORT'] || '6379'}`,
          ...(process.env['REDIS_PASSWORD'] ? { password: process.env['REDIS_PASSWORD'] } : {}),
        }) as RedisClientType;

        this.redisClient.on('error', err => {
          logger.error('Redis client error in rate limiter', { error: err });
          this.isRedisConnected = false;
        });

        this.redisClient.on('connect', () => {
          logger.info('Rate limiter Redis client connected');
          this.isRedisConnected = true;
        });

        this.redisClient.on('disconnect', () => {
          logger.info('Rate limiter Redis client disconnected');
          this.isRedisConnected = false;
        });

        await this.redisClient.connect();
      }
    } catch (error) {
      logger.error('Failed to initialize Redis for rate limiting', { error });
      logger.warn('Falling back to in-memory rate limiting');
    }
  }

  /**
   * Create a rate limiter middleware
   * @param options Rate limiter options
   * @returns Express middleware
   */
  static create(options: RateLimiterOptions): RateLimiter {
    return new RateLimiter(options, this.redisClient, this.isRedisConnected, this.localCache);
  }

  /**
   * Close Redis connection
   */
  static async close(): Promise<void> {
    if (this.redisClient && this.isRedisConnected) {
      await this.redisClient.quit();
      this.isRedisConnected = false;
    }
  }
}

/**
 * Rate Limiter Options
 */
export interface RateLimiterOptions {
  // Maximum number of requests allowed within the window
  max: number;

  // Time window in seconds
  windowSizeInSeconds: number;

  // Key prefix for Redis
  keyPrefix: string;

  // Message to send when rate limit is exceeded
  message?: string;

  // Status code to send when rate limit is exceeded
  statusCode?: number;

  // Whether to skip rate limiting for trusted proxies
  skipTrustedProxies?: boolean;

  // Whether to skip rate limiting for certain IPs
  skipIps?: string[];

  // Whether to skip rate limiting for certain user agents
  skipUserAgents?: string[];

  // Function to get the key from the request
  keyGenerator?: (req: Request) => string;

  // Function to handle the response when rate limit is exceeded
  handler?: (req: Request, res: Response) => void;

  // Whether to include headers in the response
  headers?: boolean;

  // Whether to use a sliding window
  slidingWindow?: boolean;
}

/**
 * Rate Limiter
 * Implements rate limiting middleware with Redis or in-memory storage
 */
export class RateLimiter {
  private readonly options: Required<RateLimiterOptions>;
  private readonly redisClient: RedisClientType | null;
  private readonly isRedisConnected: boolean;
  private readonly localCache: Map<string, { count: number; resetTime: number }>;

  constructor(
    options: RateLimiterOptions,
    redisClient: RedisClientType | null,
    isRedisConnected: boolean,
    localCache: Map<string, { count: number; resetTime: number }>
  ) {
    // Set default options
    this.options = {
      max: options.max,
      windowSizeInSeconds: options.windowSizeInSeconds,
      keyPrefix: options.keyPrefix,
      message: options.message || 'Too many requests, please try again later.',
      statusCode: options.statusCode || 429,
      skipTrustedProxies: options.skipTrustedProxies || false,
      skipIps: options.skipIps || [],
      skipUserAgents: options.skipUserAgents || [],
      keyGenerator: options.keyGenerator || this.defaultKeyGenerator,
      handler: options.handler || this.defaultHandler.bind(this),
      headers: options.headers !== undefined ? options.headers : true,
      slidingWindow: options.slidingWindow !== undefined ? options.slidingWindow : true,
    };

    this.redisClient = redisClient;
    this.isRedisConnected = isRedisConnected;
    this.localCache = localCache;
  }

  /**
   * Default key generator
   * @param req Express request
   * @returns Rate limiting key
   */
  private defaultKeyGenerator(req: Request): string {
    // Get client IP
    const ip = this.getClientIp(req);

    // Get route path (normalize by removing query parameters and trailing slashes)
    const path = req.path.replace(/\/$/, '').split('?')[0];

    // Combine IP and path for the key
    return `${ip}:${path}`;
  }

  /**
   * Get client IP address
   * @param req Express request
   * @returns Client IP address
   */
  private getClientIp(req: Request): string {
    // Check X-Forwarded-For header
    const forwardedFor = req.headers['x-forwarded-for'];
    if (forwardedFor) {
      // Get the first IP in the list
      const ips = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor.split(',')[0];
      return (ips || '').trim() || 'unknown';
    }

    // Fall back to connection remote address
    return req.socket.remoteAddress || 'unknown';
  }

  /**
   * Default handler for rate limit exceeded
   * @param req Express request
   * @param res Express response
   */
  private defaultHandler(req: Request, res: Response): void {
    res.status(this.options.statusCode).json({
      success: false,
      message: this.options.message,
      error: 'RATE_LIMIT_EXCEEDED',
    });
  }

  /**
   * Check if request should be rate limited
   * @param req Express request
   * @returns Whether to skip rate limiting
   */
  private shouldSkip(req: Request): boolean {
    // Skip trusted proxies
    if (this.options.skipTrustedProxies && req.ip === '127.0.0.1') {
      return true;
    }

    // Skip specific IPs
    const clientIp = this.getClientIp(req);
    if (this.options.skipIps.includes(clientIp)) {
      return true;
    }

    // Skip specific user agents
    const userAgent = req.headers['user-agent'];
    if (userAgent && this.options.skipUserAgents.some(ua => userAgent.includes(ua))) {
      return true;
    }

    return false;
  }

  /**
   * Increment counter in Redis
   * @param key Rate limiting key
   * @param windowSize Time window in seconds
   * @returns Current count and TTL
   */
  private async incrementRedisCounter(
    key: string,
    windowSize: number
  ): Promise<{ count: number; ttl: number }> {
    try {
      const redisKey = `${this.options.keyPrefix}:${key}`;

      // Use Redis pipeline for atomic operations
      const pipeline = this.redisClient!.multi();

      // Increment counter
      pipeline.incr(redisKey);

      // Set expiration if key is new
      pipeline.expire(redisKey, windowSize);

      // Get TTL
      pipeline.ttl(redisKey);

      // Execute pipeline
      const results = await pipeline.exec();

      // Extract results and safely convert to numbers
      const count = results && results[0] ? Number(results[0]) : 0;
      const ttl = results && results[2] ? Number(results[2]) : windowSize;

      return { count, ttl };
    } catch (error) {
      logger.error('Failed to increment Redis counter', { error, key });
      throw error;
    }
  }

  /**
   * Increment counter in memory
   * @param key Rate limiting key
   * @param windowSize Time window in seconds
   * @returns Current count and TTL
   */
  private incrementMemoryCounter(key: string, windowSize: number): { count: number; ttl: number } {
    const now = Date.now();
    const memoryKey = `${this.options.keyPrefix}:${key}`;

    // Get or create entry
    let entry = this.localCache.get(memoryKey);

    if (!entry || entry.resetTime <= now) {
      // Create new entry
      entry = {
        count: 1,
        resetTime: now + windowSize * 1000,
      };
      this.localCache.set(memoryKey, entry);
      return { count: 1, ttl: windowSize };
    } else {
      // Increment existing entry
      entry.count++;
      const ttl = Math.ceil((entry.resetTime - now) / 1000);
      return { count: entry.count, ttl };
    }
  }

  /**
   * Clean up expired entries in memory cache
   */
  private cleanupMemoryCache(): void {
    const now = Date.now();
    for (const [key, entry] of this.localCache.entries()) {
      if (entry.resetTime <= now) {
        this.localCache.delete(key);
      }
    }
  }

  /**
   * Express middleware
   * @param req Express request
   * @param res Express response
   * @param next Express next function
   */
  middleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Skip rate limiting if necessary
      if (this.shouldSkip(req)) {
        return next();
      }

      // Generate key
      const key = this.options.keyGenerator(req);

      // Clean up memory cache periodically
      if (Math.random() < 0.01) {
        // 1% chance to clean up
        this.cleanupMemoryCache();
      }

      // Increment counter
      let count: number;
      let ttl: number;

      if (this.isRedisConnected && this.redisClient) {
        // Use Redis
        const result = await this.incrementRedisCounter(key, this.options.windowSizeInSeconds);
        count = result.count;
        ttl = result.ttl;
      } else {
        // Use memory
        const result = this.incrementMemoryCounter(key, this.options.windowSizeInSeconds);
        count = result.count;
        ttl = result.ttl;
      }

      // Set headers if enabled
      if (this.options.headers) {
        res.setHeader('X-RateLimit-Limit', this.options.max.toString());
        res.setHeader('X-RateLimit-Remaining', Math.max(0, this.options.max - count).toString());
        res.setHeader('X-RateLimit-Reset', Math.ceil(Date.now() / 1000 + ttl).toString());
      }

      // Check if rate limit exceeded
      if (count > this.options.max) {
        if (this.options.headers) {
          res.setHeader('Retry-After', ttl.toString());
        }
        return this.options.handler(req, res);
      }

      // Continue
      next();
    } catch (error) {
      logger.error('Rate limiting error', { error, path: req.path });
      next(); // Continue on error
    }
  };
}

// Initialize Redis client
RateLimiterFactory.initializeRedis().catch(err => {
  logger.error('Failed to initialize Redis for rate limiting', { error: err });
});

// Export pre-configured rate limiters
export const loginLimiter = RateLimiterFactory.create({
  max: securityConfig.rateLimit.login.maxAttempts,
  windowSizeInSeconds: securityConfig.rateLimit.login.windowSizeInSeconds,
  keyPrefix: 'rate-limit:login',
  message: 'Too many login attempts, please try again later.',
});

export const registrationLimiter = RateLimiterFactory.create({
  max: securityConfig.rateLimit.registration.maxAttempts,
  windowSizeInSeconds: securityConfig.rateLimit.registration.windowSizeInSeconds,
  keyPrefix: 'rate-limit:registration',
  message: 'Too many registration attempts, please try again later.',
});

export const passwordResetLimiter = RateLimiterFactory.create({
  max: securityConfig.rateLimit.passwordReset.maxAttempts,
  windowSizeInSeconds: securityConfig.rateLimit.passwordReset.windowSizeInSeconds,
  keyPrefix: 'rate-limit:password-reset',
  message: 'Too many password reset attempts, please try again later.',
});

export const apiLimiter = RateLimiterFactory.create({
  max: securityConfig.rateLimit.api.maxRequests,
  windowSizeInSeconds: securityConfig.rateLimit.api.windowSizeInSeconds,
  keyPrefix: 'rate-limit:api',
  message: 'Too many API requests, please try again later.',
});
