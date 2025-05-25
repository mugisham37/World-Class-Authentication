import { createClient, type RedisClientType } from 'redis';
import { performanceConfig } from '../../config/performance-config';
import { logger } from '../../infrastructure/logging/logger';
import { Injectable } from './injectable';

/**
 * Cache service for performance optimization
 * Implements multi-level caching strategy with Redis
 */
@Injectable()
export class CacheService {
  private redisClient: RedisClientType<any>;
  private localCache: Map<string, { value: any; expiry: number }>;
  private isConnected = false;
  private readonly keyPrefix: string;

  constructor() {
    // Initialize local in-memory cache
    this.localCache = new Map();
    this.keyPrefix = process.env['REDIS_KEY_PREFIX'] || 'auth';

    // Initialize Redis client with type assertion to avoid TypeScript errors
    this.redisClient = createClient({
      url: `redis://${process.env['REDIS_HOST'] || 'localhost'}:${process.env['REDIS_PORT'] || '6379'}`,
      ...(process.env['REDIS_PASSWORD'] ? { password: process.env['REDIS_PASSWORD'] } : {}),
      database: Number.parseInt(process.env['REDIS_DB'] || '0'),
    } as any);

    // Set up event handlers
    this.redisClient.on('error', (err: Error) => {
      logger.error('Redis client error in CacheService', { error: err });
    });

    this.redisClient.on('connect', () => {
      logger.info('CacheService Redis client connected');
      this.isConnected = true;
    });

    this.redisClient.on('disconnect', () => {
      logger.info('CacheService Redis client disconnected');
      this.isConnected = false;
    });

    // Connect to Redis
    this.connect().catch(err => {
      logger.error('Failed to connect to Redis in CacheService', { error: err });
    });
  }

  /**
   * Connect to Redis
   */
  private async connect(): Promise<void> {
    try {
      await this.redisClient.connect();
    } catch (error) {
      logger.error('Failed to connect to Redis in CacheService', { error });
      // Don't throw error, we'll fall back to local cache
    }
  }

  /**
   * Get value from cache
   * @param key Cache key
   * @param options Cache options
   * @returns Cached value or null if not found
   */
  async get<T>(
    key: string,
    options: {
      useLocalCache?: boolean;
      parseJson?: boolean;
    } = {}
  ): Promise<T | null> {
    const { useLocalCache = true, parseJson = true } = options;
    const fullKey = this.getFullKey(key);

    try {
      // Try local cache first if enabled
      if (useLocalCache) {
        const localValue = this.getFromLocalCache<T>(fullKey);
        if (localValue !== null) {
          return localValue;
        }
      }

      // If not in local cache or local cache disabled, try Redis
      if (this.isConnected) {
        const value = await this.redisClient.get(fullKey);
        if (value) {
          // Parse JSON if needed
          const parsedValue = parseJson && typeof value === 'string' ? JSON.parse(value) : value;

          // Store in local cache if enabled
          if (useLocalCache) {
            const ttl = await this.redisClient.ttl(fullKey);
            if (ttl > 0) {
              this.setInLocalCache(fullKey, parsedValue, ttl);
            }
          }

          return parsedValue as T;
        }
      }

      return null;
    } catch (error) {
      logger.error('Failed to get from cache', { error, key });
      return null;
    }
  }

  /**
   * Set value in cache
   * @param key Cache key
   * @param value Value to cache
   * @param options Cache options
   * @returns Success status
   */
  async set(
    key: string,
    value: any,
    options: {
      ttl?: number;
      useLocalCache?: boolean;
      stringifyJson?: boolean;
    } = {}
  ): Promise<boolean> {
    const {
      ttl = performanceConfig.cache.defaultTtl,
      useLocalCache = true,
      stringifyJson = true,
    } = options;
    const fullKey = this.getFullKey(key);

    try {
      // Store in local cache if enabled
      if (useLocalCache) {
        this.setInLocalCache(fullKey, value, ttl);
      }

      // Store in Redis
      if (this.isConnected) {
        const stringValue = stringifyJson ? JSON.stringify(value) : value;
        await this.redisClient.set(fullKey, stringValue, { EX: ttl });
      }

      return true;
    } catch (error) {
      logger.error('Failed to set in cache', { error, key });
      return false;
    }
  }

  /**
   * Delete value from cache
   * @param key Cache key
   * @param options Cache options
   * @returns Success status
   */
  async delete(
    key: string,
    options: {
      useLocalCache?: boolean;
    } = {}
  ): Promise<boolean> {
    const { useLocalCache = true } = options;
    const fullKey = this.getFullKey(key);

    try {
      // Delete from local cache if enabled
      if (useLocalCache) {
        this.localCache.delete(fullKey);
      }

      // Delete from Redis
      if (this.isConnected) {
        await this.redisClient.del(fullKey);
      }

      return true;
    } catch (error) {
      logger.error('Failed to delete from cache', { error, key });
      return false;
    }
  }

  /**
   * Clear all cache
   * @param options Cache options
   * @returns Success status
   */
  async clear(
    options: {
      useLocalCache?: boolean;
      pattern?: string;
    } = {}
  ): Promise<boolean> {
    const { useLocalCache = true, pattern } = options;

    try {
      // Clear local cache if enabled
      if (useLocalCache) {
        if (pattern) {
          const fullPattern = this.getFullKey(pattern);
          // Convert Map keys to array before iteration to avoid ES2015+ iterator requirement
          const keys = Array.from(this.localCache.keys());
          keys.forEach(key => {
            if (key.startsWith(fullPattern)) {
              this.localCache.delete(key);
            }
          });
        } else {
          this.localCache.clear();
        }
      }

      // Clear Redis
      if (this.isConnected) {
        if (pattern) {
          const fullPattern = this.getFullKey(pattern);
          const keys = await this.redisClient.keys(`${fullPattern}*`);
          if (keys && keys.length > 0) {
            // Filter out any undefined keys before passing to del
            const validKeys = keys.filter((key): key is string => key !== undefined);
            if (validKeys.length > 0) {
              await this.redisClient.del(validKeys);
            }
          }
        } else {
          await this.redisClient.flushDb();
        }
      }

      return true;
    } catch (error) {
      logger.error('Failed to clear cache', { error, pattern });
      return false;
    }
  }

  /**
   * Get multiple values from cache
   * @param keys Array of cache keys
   * @param options Cache options
   * @returns Object with keys and values
   */
  async mget<T>(
    keys: string[],
    options: {
      useLocalCache?: boolean;
      parseJson?: boolean;
    } = {}
  ): Promise<Record<string, T | null>> {
    const { useLocalCache = true, parseJson = true } = options;
    const result: Record<string, T | null> = {};

    try {
      // Initialize result with null values for all keys
      for (const key of keys) {
        result[key] = null;
      }

      if (keys.length === 0) {
        return result;
      }

      // Create full keys and track which ones need to be fetched from Redis
      const keysToFetch: string[] = [];
      const keyMapping: Map<string, string> = new Map();

      // Check local cache first if enabled
      if (useLocalCache) {
        for (let i = 0; i < keys.length; i++) {
          const originalKey = keys[i];
          if (!originalKey) continue; // Skip undefined keys

          const fullKey = this.getFullKey(originalKey);

          // Try to get from local cache
          const localValue = this.getFromLocalCache<T>(fullKey);
          if (localValue !== null) {
            result[originalKey] = localValue;
          } else {
            keysToFetch.push(fullKey);
            keyMapping.set(fullKey, originalKey);
          }
        }
      } else {
        // Skip local cache, fetch all from Redis
        for (let i = 0; i < keys.length; i++) {
          const originalKey = keys[i];
          if (!originalKey) continue; // Skip undefined keys

          const fullKey = this.getFullKey(originalKey);
          keysToFetch.push(fullKey);
          keyMapping.set(fullKey, originalKey);
        }
      }

      // If all keys were found in local cache, return early
      if (keysToFetch.length === 0) {
        return result;
      }

      // Fetch remaining keys from Redis
      if (this.isConnected) {
        const values = await this.redisClient.mGet(keysToFetch);

        for (let i = 0; i < values.length; i++) {
          const value = values[i];
          const fullKey = keysToFetch[i]; // This was the source of the error

          // Add null check for fullKey to fix TypeScript error
          if (value && fullKey) {
            const originalKey = keyMapping.get(fullKey);

            if (originalKey) {
              // Parse JSON if needed
              const parsedValue =
                parseJson && typeof value === 'string' ? JSON.parse(value) : value;

              result[originalKey] = parsedValue as T;

              // Update local cache if enabled
              if (useLocalCache) {
                this.redisClient
                  .ttl(fullKey)
                  .then(ttl => {
                    if (ttl > 0) {
                      this.setInLocalCache(fullKey, parsedValue, ttl);
                    }
                  })
                  .catch(error => {
                    logger.error('Failed to get TTL for cache key', { error, key: fullKey });
                  });
              }
            }
          }
        }
      }

      return result;
    } catch (error) {
      logger.error('Failed to get multiple values from cache', { error, keys });
      return result;
    }
  }

  /**
   * Set multiple values in cache
   * @param entries Object with keys and values
   * @param options Cache options
   * @returns Success status
   */
  async mset(
    entries: Record<string, any>,
    options: {
      ttl?: number;
      useLocalCache?: boolean;
      stringifyJson?: boolean;
    } = {}
  ): Promise<boolean> {
    const {
      ttl = performanceConfig.cache.defaultTtl,
      useLocalCache = true,
      stringifyJson = true,
    } = options;

    try {
      // Store in Redis
      if (this.isConnected) {
        const pipeline = this.redisClient.multi();

        for (const [key, value] of Object.entries(entries)) {
          if (!key) continue; // Skip undefined/empty keys

          const fullKey = this.getFullKey(key);
          const stringValue = stringifyJson ? JSON.stringify(value) : value;

          // Add to Redis pipeline
          pipeline.set(fullKey, stringValue, { EX: ttl });

          // Store in local cache if enabled
          if (useLocalCache) {
            this.setInLocalCache(fullKey, value, ttl);
          }
        }

        // Execute pipeline
        await pipeline.exec();
      } else if (useLocalCache) {
        // If Redis is not connected, just store in local cache
        for (const [key, value] of Object.entries(entries)) {
          if (!key) continue; // Skip undefined/empty keys

          const fullKey = this.getFullKey(key);
          this.setInLocalCache(fullKey, value, ttl);
        }
      }

      return true;
    } catch (error) {
      logger.error('Failed to set multiple values in cache', { error });
      return false;
    }
  }

  /**
   * Increment a counter in cache
   * @param key Cache key
   * @param increment Increment value
   * @param options Cache options
   * @returns New value or null if failed
   */
  async increment(
    key: string,
    increment = 1,
    options: {
      ttl?: number;
      useLocalCache?: boolean;
    } = {}
  ): Promise<number | null> {
    const { ttl, useLocalCache = true } = options;
    const fullKey = this.getFullKey(key);

    try {
      let newValue: number | null = null;

      // Increment in Redis
      if (this.isConnected) {
        newValue = await this.redisClient.incrBy(fullKey, increment);

        // Set TTL if provided
        if (ttl !== undefined) {
          await this.redisClient.expire(fullKey, ttl);
        }

        // Update local cache if enabled
        if (useLocalCache) {
          this.setInLocalCache(fullKey, newValue, ttl || performanceConfig.cache.defaultTtl);
        }
      } else if (useLocalCache) {
        // If Redis is not connected, use local cache
        const localValue = this.getFromLocalCache<number>(fullKey) || 0;
        newValue = localValue + increment;
        this.setInLocalCache(fullKey, newValue, ttl || performanceConfig.cache.defaultTtl);
      }

      return newValue;
    } catch (error) {
      logger.error('Failed to increment counter in cache', { error, key });
      return null;
    }
  }

  /**
   * Get value from local cache
   * @param key Cache key
   * @returns Cached value or null if not found
   */
  private getFromLocalCache<T>(key: string): T | null {
    const item = this.localCache.get(key);
    if (item && item.expiry > Date.now()) {
      return item.value as T;
    }

    // Remove expired item
    if (item) {
      this.localCache.delete(key);
    }

    return null;
  }

  /**
   * Set value in local cache
   * @param key Cache key
   * @param value Value to cache
   * @param ttl Time to live in seconds
   */
  private setInLocalCache(key: string, value: any, ttl: number): void {
    const expiry = Date.now() + ttl * 1000;
    this.localCache.set(key, { value, expiry });

    // Schedule cleanup of expired items
    this.scheduleLocalCacheCleanup();
  }

  /**
   * Schedule cleanup of expired items in local cache
   */
  private scheduleLocalCacheCleanup(): void {
    if (this.localCache.size > performanceConfig.cache.localCacheMaxSize) {
      // Clean up expired items
      const now = Date.now();
      // Convert Map entries to array before iteration to avoid ES2015+ iterator requirement
      const entries = Array.from(this.localCache.entries());
      entries.forEach(([key, item]) => {
        if (item.expiry <= now) {
          this.localCache.delete(key);
        }
      });

      // If still too large, remove oldest items
      if (this.localCache.size > performanceConfig.cache.localCacheMaxSize) {
        const itemsToRemove = this.localCache.size - performanceConfig.cache.localCacheMaxSize;
        const keys = Array.from(this.localCache.keys()).slice(0, itemsToRemove);
        for (const key of keys) {
          this.localCache.delete(key);
        }
      }
    }
  }

  /**
   * Get full cache key with prefix
   * @param key Cache key
   * @returns Full cache key
   */
  private getFullKey(key: string): string {
    return `${this.keyPrefix}:${key}`;
  }

  /**
   * Get cache statistics
   * @returns Cache statistics
   */
  async getStats(): Promise<Record<string, any>> {
    const stats: Record<string, any> = {
      localCache: {
        size: this.localCache.size,
        maxSize: performanceConfig.cache.localCacheMaxSize,
      },
    };

    if (this.isConnected) {
      try {
        // Get Redis info
        const info = await this.redisClient.info();
        // Helper function to safely extract Redis info values
        const extractInfoValue = (pattern: RegExp): string => {
          const match = info.match(pattern);
          return match?.[1]?.trim() || 'N/A';
        };

        // Extract Redis metrics with safe pattern matching
        const memory = extractInfoValue(/used_memory_human:(.+?)\r\n/);
        const clients = extractInfoValue(/connected_clients:(.+?)\r\n/);
        const uptime = extractInfoValue(/uptime_in_seconds:(.+?)\r\n/);

        stats['redis'] = {
          connected: this.isConnected,
          memory,
          clients,
          uptime,
        };

        // Get key count for our prefix
        const keyPattern = `${this.keyPrefix}:*`;
        const keys = await this.redisClient.keys(keyPattern);

        if (Array.isArray(keys)) {
          stats['redis'].keys = keys.length;
        }
      } catch (error) {
        logger.error('Failed to get Redis stats', { error });
        stats['redis'] = { connected: this.isConnected, error: 'Failed to get Redis stats' };
      }
    } else {
      stats['redis'] = { connected: false };
    }

    return stats;
  }

  /**
   * Close Redis connection
   */
  async close(): Promise<void> {
    try {
      if (this.isConnected) {
        await this.redisClient.quit();
        this.isConnected = false;
      }
    } catch (error) {
      logger.error('Failed to close Redis connection in CacheService', { error });
    }
  }
}
