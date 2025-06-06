import type { NextFunction, Request, Response } from 'express';
import { createClient } from 'redis';
import { dbConfig } from '../../config/database.config';
import { env } from '../../config/environment';
import { logger } from '../../infrastructure/logging/logger';
import { AppError } from '../../utils/error-handling';
import { getCurrentCorrelationId } from './correlation-id.middleware';

/**
 * Rate limit error
 */
class RateLimitError extends AppError {
  constructor(message: string, code: string = 'RATE_LIMIT_EXCEEDED') {
    super(message, code);
  }
}

/**
 * Rate limit information
 */
interface RateLimitInfo {
  totalHits: number;
  resetTime: Date;
  remainingHits: number;
}

/**
 * Rate limit store interface
 */
interface RateLimitStore {
  init?: () => Promise<void>;
  increment: (key: string) => Promise<RateLimitInfo>;
  decrement?: (key: string) => Promise<void>;
  resetKey?: (key: string) => Promise<void>;
  resetAll?: () => Promise<void>;
}

/**
 * Rate limit options
 */
interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  message: string;
  statusCode: number;
  skipSuccessfulRequests: boolean;
  skipFailedRequests: boolean;
  skipMethods?: string[];
  skipPaths?: string[];
  keyGenerator: (req: Request) => string;
  handler: (req: Request, res: Response, next: NextFunction, options: RateLimitOptions) => void;
  headers: boolean;
  draft: boolean;
  standardHeaders: boolean;
  legacyHeaders: boolean;
  store: RateLimitStore;
}

/**
 * Create Redis client for rate limiting
 */
let redisClient: ReturnType<typeof createClient> | null = null;

/**
 * Initialize Redis client
 */
async function initRedisClient(): Promise<ReturnType<typeof createClient>> {
  if (redisClient) {
    return redisClient;
  }

  try {
    redisClient = createClient({
      url: `redis://${dbConfig.redis.host}:${dbConfig.redis.port}`,
      password: dbConfig.redis.password,
    });

    // Handle Redis errors
    redisClient.on('error', error => {
      logger.error('Redis client error', { error });
    });

    // Connect to Redis
    await redisClient.connect();
    logger.info('Redis client connected for rate limiting');

    return redisClient;
  } catch (error) {
    logger.error('Failed to connect Redis client for rate limiting', { error });
    throw error;
  }
}

/**
 * Memory store for rate limiting
 * Used as a fallback when Redis is not available
 */
class MemoryStore implements RateLimitStore {
  private cache: Map<string, { hits: number; resetTime: Date }>;
  private options: { windowMs: number; maxRequests: number };

  constructor(options: { windowMs: number; maxRequests: number }) {
    this.cache = new Map();
    this.options = options;

    // Clean up expired entries periodically
    setInterval(() => {
      const now = new Date();
      for (const [key, value] of this.cache.entries()) {
        if (value.resetTime < now) {
          this.cache.delete(key);
        }
      }
    }, 60 * 1000); // Clean up every minute
  }

  async increment(key: string): Promise<RateLimitInfo> {
    const now = new Date();
    let entry = this.cache.get(key);

    // If entry doesn't exist or has expired, create a new one
    if (!entry || entry.resetTime < now) {
      const resetTime = new Date(now.getTime() + this.options.windowMs);
      entry = { hits: 0, resetTime };
      this.cache.set(key, entry);
    }

    // Increment hits
    entry.hits += 1;

    // Calculate remaining hits
    const remainingHits = Math.max(0, this.options.maxRequests - entry.hits);

    return {
      totalHits: entry.hits,
      resetTime: entry.resetTime,
      remainingHits,
    };
  }

  async decrement(key: string): Promise<void> {
    const entry = this.cache.get(key);
    if (entry && entry.hits > 0) {
      entry.hits -= 1;
    }
  }

  async resetKey(key: string): Promise<void> {
    this.cache.delete(key);
  }

  async resetAll(): Promise<void> {
    this.cache.clear();
  }
}

/**
 * Redis store for rate limiting
 */
class RedisStore implements RateLimitStore {
  private client: ReturnType<typeof createClient> | null = null;
  private options: { windowMs: number; maxRequests: number; prefix: string };
  private ready: boolean = false;

  constructor(options: { windowMs: number; maxRequests: number; prefix: string }) {
    this.options = options;
  }

  async init(): Promise<void> {
    try {
      this.client = await initRedisClient();
      this.ready = true;
    } catch (error) {
      logger.error('Failed to initialize Redis store', { error });
      this.ready = false;
    }
  }

  async increment(key: string): Promise<RateLimitInfo> {
    // If Redis is not available, use memory store as fallback
    if (!this.ready || !this.client) {
      logger.warn('Redis store not ready, using memory store as fallback');
      const memoryStore = new MemoryStore({
        windowMs: this.options.windowMs,
        maxRequests: this.options.maxRequests,
      });
      return memoryStore.increment(key);
    }

    const redisKey = `${this.options.prefix}:${key}`;
    const now = Date.now();

    try {
      // Use Redis transaction to ensure atomicity
      const multi = this.client.multi();

      // Increment hits
      multi.incr(redisKey);

      // Set expiration if key is new
      multi.pExpire(redisKey, this.options.windowMs);

      // Get current hits
      multi.get(redisKey);

      // Get TTL
      multi.pTTL(redisKey);

      // Execute transaction
      const results = await multi.exec();

      // Parse results - safely cast Redis responses to string
      const hitsStr = results?.[2]?.toString() || '0';
      const ttlStr = results?.[3]?.toString() || this.options.windowMs.toString();

      const totalHits = parseInt(hitsStr, 10);
      const ttl = parseInt(ttlStr, 10);

      // Calculate remaining hits
      const remainingHits = Math.max(0, this.options.maxRequests - totalHits);

      // Calculate reset time
      const calculatedResetTime = new Date(now + ttl);

      return {
        totalHits,
        resetTime: calculatedResetTime,
        remainingHits,
      };
    } catch (error) {
      logger.error('Redis store increment error', { error, key });

      // Fallback to memory store
      const memoryStore = new MemoryStore({
        windowMs: this.options.windowMs,
        maxRequests: this.options.maxRequests,
      });
      return memoryStore.increment(key);
    }
  }

  async decrement(key: string): Promise<void> {
    if (!this.ready || !this.client) {
      return;
    }

    const redisKey = `${this.options.prefix}:${key}`;

    try {
      // Get current hits
      const hits = await this.client.get(redisKey);

      if (hits && parseInt(hits.toString(), 10) > 0) {
        // Decrement hits
        await this.client.decr(redisKey);
      }
    } catch (error) {
      logger.error('Redis store decrement error', { error, key });
    }
  }

  async resetKey(key: string): Promise<void> {
    if (!this.ready || !this.client) {
      return;
    }

    const redisKey = `${this.options.prefix}:${key}`;

    try {
      await this.client.del(redisKey);
    } catch (error) {
      logger.error('Redis store resetKey error', { error, key });
    }
  }

  async resetAll(): Promise<void> {
    if (!this.ready || !this.client) {
      return;
    }

    try {
      const keys = await this.client.keys(`${this.options.prefix}:*`);
      if (keys.length > 0) {
        await this.client.del(keys);
      }
    } catch (error) {
      logger.error('Redis store resetAll error', { error });
    }
  }
}

/**
 * Default rate limit handler
 * @param req Express request
 * @param res Response
 * @param next NextFunction
 * @param options Rate limit options
 */
function defaultRateLimitHandler(
  req: Request,
  res: Response,
  next: NextFunction,
  options: RateLimitOptions
): void {
  const correlationId =
    getCurrentCorrelationId() || (req.headers['x-correlation-id'] as string) || 'unknown';

  logger.warn(`[${correlationId}] Rate limit exceeded`, {
    ip: req.ip || req.socket.remoteAddress,
    path: req.path,
    method: req.method,
    headers: req.headers,
  });

  next(new RateLimitError(options.message));
}

/**
 * Default key generator
 * @param req Express request
 * @returns Rate limit key
 */
function defaultKeyGenerator(req: Request): string {
  // Use user ID if available, otherwise use IP
  if (req.user?.id) {
    return `user:${req.user.id}`;
  }

  // Use device ID if available
  if (req.deviceId) {
    return `device:${req.deviceId}`;
  }

  // Fallback to IP
  return `ip:${req.ip || req.socket.remoteAddress || 'unknown'}`;
}

/**
 * Create rate limit middleware
 * @param options Rate limit options
 * @returns Rate limit middleware
 */
export function createRateLimiter(
  options: Partial<RateLimitOptions> = {}
): (req: Request, res: Response, next: NextFunction) => Promise<void> {
  // Default options
  const defaultOptions: RateLimitOptions = {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 100, // 100 requests per minute
    message: 'Too many requests, please try again later',
    statusCode: 429,
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
    keyGenerator: defaultKeyGenerator,
    handler: defaultRateLimitHandler,
    headers: true,
    draft: false,
    standardHeaders: true,
    legacyHeaders: false,
    store: new RedisStore({
      windowMs: options.windowMs || 60 * 1000,
      maxRequests: options.maxRequests || 100,
      prefix: 'ratelimit',
    }),
  };

  // Merge options
  const mergedOptions: RateLimitOptions = { ...defaultOptions, ...options };

  // Initialize store
  if (mergedOptions.store.init) {
    mergedOptions.store.init().catch(error => {
      logger.error('Failed to initialize rate limit store', { error });
    });
  }

  // Return middleware
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Skip if disabled
    if ((env.get('RATE_LIMITING_ENABLED', 'true') || 'true').toLowerCase() === 'false') {
      return next();
    }

    // Skip for specified methods
    if (mergedOptions.skipMethods && mergedOptions.skipMethods.includes(req.method)) {
      return next();
    }

    // Skip for specified paths
    if (
      mergedOptions.skipPaths &&
      mergedOptions.skipPaths.some(path => req.path.startsWith(path))
    ) {
      return next();
    }

    try {
      // Generate key
      const key = mergedOptions.keyGenerator(req);

      // Increment hits
      const rateLimitInfo = await mergedOptions.store.increment(key);

      // Check if rate limit is exceeded
      if (rateLimitInfo.remainingHits <= 0) {
        // Set rate limit headers
        if (mergedOptions.headers) {
          if (mergedOptions.standardHeaders) {
            res.setHeader('RateLimit-Limit', mergedOptions.maxRequests);
            res.setHeader('RateLimit-Remaining', 0);
            res.setHeader('RateLimit-Reset', Math.ceil(rateLimitInfo.resetTime.getTime() / 1000));
          }

          if (mergedOptions.legacyHeaders) {
            res.setHeader('X-RateLimit-Limit', mergedOptions.maxRequests);
            res.setHeader('X-RateLimit-Remaining', 0);
            res.setHeader('X-RateLimit-Reset', Math.ceil(rateLimitInfo.resetTime.getTime() / 1000));
            res.setHeader(
              'Retry-After',
              Math.ceil((rateLimitInfo.resetTime.getTime() - Date.now()) / 1000)
            );
          }
        }

        // Call handler
        return mergedOptions.handler(req, res, next, mergedOptions);
      }

      // Set rate limit headers
      if (mergedOptions.headers) {
        if (mergedOptions.standardHeaders) {
          res.setHeader('RateLimit-Limit', mergedOptions.maxRequests);
          res.setHeader('RateLimit-Remaining', rateLimitInfo.remainingHits);
          res.setHeader('RateLimit-Reset', Math.ceil(rateLimitInfo.resetTime.getTime() / 1000));
        }

        if (mergedOptions.legacyHeaders) {
          res.setHeader('X-RateLimit-Limit', mergedOptions.maxRequests);
          res.setHeader('X-RateLimit-Remaining', rateLimitInfo.remainingHits);
          res.setHeader('X-RateLimit-Reset', Math.ceil(rateLimitInfo.resetTime.getTime() / 1000));
        }
      }

      // Handle successful requests
      if (mergedOptions.skipSuccessfulRequests) {
        res.on('finish', () => {
          if (res.statusCode < 400 && mergedOptions.store.decrement) {
            mergedOptions.store.decrement(key).catch(error => {
              logger.error('Failed to decrement rate limit', { error, key });
            });
          }
        });
      }

      // Handle failed requests
      if (mergedOptions.skipFailedRequests) {
        res.on('finish', () => {
          if (res.statusCode >= 400 && mergedOptions.store.decrement) {
            mergedOptions.store.decrement(key).catch(error => {
              logger.error('Failed to decrement rate limit', { error, key });
            });
          }
        });
      }

      next();
    } catch (error) {
      logger.error('Rate limiting middleware error', {
        error,
        correlationId: getCurrentCorrelationId(),
      });
      next();
    }
  };
}

/**
 * Default rate limiter for general API endpoints
 * 100 requests per minute
 */
export const defaultRateLimiter = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 100, // 100 requests per minute
  message: 'Too many requests, please try again later',
});

/**
 * Strict rate limiter for sensitive operations
 * 10 requests per hour
 */
export const strictRateLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 10, // 10 requests per hour
  message: 'Too many sensitive operations, please try again later',
});

/**
 * Authentication rate limiter
 * 5 attempts per 15 minutes
 */
export const authRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 5, // 5 attempts per 15 minutes
  message: 'Too many authentication attempts, please try again later',
  skipSuccessfulRequests: true, // Don't count successful logins
});

/**
 * API rate limiter
 * 1000 requests per hour
 */
export const apiRateLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 1000, // 1000 requests per hour
  message: 'API rate limit exceeded, please try again later',
});

/**
 * User-specific rate limiter
 * 100 requests per minute per user
 */
export const userRateLimiter = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 100, // 100 requests per minute
  message: 'Too many requests, please try again later',
  keyGenerator: (req: Request): string => {
    return req.user?.id ? `user:${req.user.id}` : defaultKeyGenerator(req);
  },
});
