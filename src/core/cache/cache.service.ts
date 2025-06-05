import { Injectable } from '@tsed/di';
import { redisCache } from '../../data/connections/redis';
import { logger } from '../../infrastructure/logging/logger';
import { databaseConfig } from '../../config/database-config';

/**
 * Cache service for storing and retrieving data
 * Uses Redis for persistent caching with a multi-level caching strategy
 */
@Injectable()
export class CacheService {
  private readonly defaultTtl: number;

  constructor() {
    this.defaultTtl = databaseConfig.redis.ttl;
  }

  /**
   * Get a value from the cache
   * @param key Cache key
   * @returns Cached value or null if not found
   */
  async get<T>(key: string): Promise<T | null> {
    try {
      return await redisCache.get<T>(key);
    } catch (error) {
      logger.error('Failed to get value from cache', { key, error });
      return null;
    }
  }

  /**
   * Set a value in the cache
   * @param key Cache key
   * @param value Value to cache
   * @param ttl Time to live in seconds
   */
  async set(key: string, value: any, ttl?: number): Promise<void> {
    try {
      await redisCache.set(key, value, ttl || this.defaultTtl);
    } catch (error) {
      logger.error('Failed to set value in cache', { key, error });
    }
  }

  /**
   * Delete a value from the cache
   * @param key Cache key
   */
  async delete(key: string): Promise<void> {
    try {
      await redisCache.delete(key);
    } catch (error) {
      logger.error('Failed to delete value from cache', { key, error });
    }
  }

  /**
   * Clear all values from the cache
   */
  async clear(): Promise<void> {
    try {
      // Clear memory cache
      redisCache.clearMemoryCache();

      // We don't flush the entire Redis database as that could affect other services
      // Instead, we would implement a more targeted approach if needed
      logger.info('Cache cleared (memory only)');
    } catch (error) {
      logger.error('Failed to clear cache', { error });
    }
  }

  /**
   * Get multiple values from the cache
   * @param keys Array of cache keys
   * @returns Object with keys and values
   */
  async mget<T>(keys: string[]): Promise<Record<string, T | null>> {
    try {
      return await redisCache.mget<T>(keys);
    } catch (error) {
      logger.error('Failed to get multiple values from cache', { keys, error });
      // Return empty object with null values
      return keys.reduce(
        (acc, key) => {
          acc[key] = null;
          return acc;
        },
        {} as Record<string, T | null>
      );
    }
  }

  /**
   * Set multiple values in the cache
   * @param entries Object with keys and values
   * @param ttl Time to live in seconds
   */
  async mset(entries: Record<string, any>, ttl?: number): Promise<void> {
    try {
      await redisCache.mset(entries, ttl || this.defaultTtl);
    } catch (error) {
      logger.error('Failed to set multiple values in cache', { entries, error });
    }
  }

  /**
   * Increment a counter in the cache
   * @param key Cache key
   * @param increment Increment value (default: 1)
   * @returns The new value
   */
  async increment(key: string, increment = 1): Promise<number | null> {
    try {
      return await redisCache.increment(key, increment);
    } catch (error) {
      logger.error('Failed to increment counter in cache', { key, error });
      return null;
    }
  }

  /**
   * Check if a key exists in the cache
   * @param key Cache key
   * @returns True if the key exists, false otherwise
   */
  async exists(key: string): Promise<boolean> {
    try {
      return await redisCache.exists(key);
    } catch (error) {
      logger.error('Failed to check if key exists in cache', { key, error });
      return false;
    }
  }
}
