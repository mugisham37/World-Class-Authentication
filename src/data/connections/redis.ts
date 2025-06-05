import {
  createClient,
  type RedisClientOptions,
  type RedisClientType,
  type RedisFunctions,
  type RedisModules,
  type RedisScripts,
} from 'redis';
import { databaseConfig } from '../../config/database-config';
import { logger } from '../../infrastructure/logging/logger';
import { DatabaseError } from '../../utils/error-handling';

// Define a specific Redis client type with all required type parameters
type TypedRedisClient = RedisClientType<RedisModules, RedisFunctions, RedisScripts>;

/**
 * Redis connection configuration
 */
const redisConfig: RedisClientOptions = {
  url: `redis://${databaseConfig.redis?.host || 'localhost'}:${databaseConfig.redis?.port || 6379}`,
  // Only include password if it exists
  ...(databaseConfig.redis?.password ? { password: databaseConfig.redis.password } : {}),
  database: databaseConfig.redis?.db || 0,
  socket: {
    reconnectStrategy: retries => {
      // Exponential backoff with max delay of 10 seconds
      const delay = Math.min(Math.pow(2, retries) * 100, 10000);
      logger.debug(`Redis reconnect attempt ${retries}, retrying in ${delay}ms`);
      return delay;
    },
    connectTimeout: 5000, // Default connection timeout
  },
};

/**
 * Redis connection manager singleton
 * Implements connection pooling, health monitoring, and circuit breaker pattern
 */
class RedisConnectionManager {
  private static instance: TypedRedisClient;
  private static isInitialized = false;
  private static connectionFailures = 0;
  private static circuitOpen = false;
  private static circuitResetTimeout: NodeJS.Timeout | null = null;
  private static subscribers: Map<string, TypedRedisClient> = new Map();
  private static healthCheckInterval: NodeJS.Timeout | null = null;

  // Circuit breaker configuration
  private static readonly CIRCUIT_THRESHOLD = 5; // Number of failures before opening circuit
  private static readonly CIRCUIT_RESET_TIMEOUT = 30000; // 30 seconds before trying again

  /**
   * Get the Redis client instance
   * Creates a new instance if one doesn't exist
   */
  public static getInstance(): TypedRedisClient {
    if (RedisConnectionManager.circuitOpen) {
      throw new DatabaseError(
        'Redis circuit breaker is open due to multiple connection failures',
        'REDIS_CIRCUIT_OPEN'
      );
    }

    if (!RedisConnectionManager.instance) {
      RedisConnectionManager.instance = createClient(redisConfig) as TypedRedisClient;

      // Set up event handlers
      RedisConnectionManager.setupEventHandlers();

      // Start health check interval
      RedisConnectionManager.startHealthCheck();
    }

    return RedisConnectionManager.instance;
  }

  /**
   * Set up event handlers for the Redis client
   */
  private static setupEventHandlers(): void {
    const client = RedisConnectionManager.instance;

    client.on('error', err => {
      logger.error('Redis client error', { error: err });
      RedisConnectionManager.handleConnectionFailure();
    });

    client.on('connect', () => {
      logger.info('Redis client connected');
    });

    client.on('ready', () => {
      logger.info('Redis client ready');
      // Reset connection failures on successful connection
      RedisConnectionManager.connectionFailures = 0;
    });

    client.on('reconnecting', () => {
      logger.info('Redis client reconnecting');
    });

    client.on('end', () => {
      logger.info('Redis client connection closed');
      RedisConnectionManager.isInitialized = false;
    });
  }

  /**
   * Handle connection failure and implement circuit breaker pattern
   */
  private static handleConnectionFailure(): void {
    RedisConnectionManager.connectionFailures++;

    if (RedisConnectionManager.connectionFailures >= RedisConnectionManager.CIRCUIT_THRESHOLD) {
      if (!RedisConnectionManager.circuitOpen) {
        logger.warn(
          `Redis circuit breaker opened after ${RedisConnectionManager.connectionFailures} failures`
        );
        RedisConnectionManager.circuitOpen = true;

        // Set timeout to reset circuit breaker
        RedisConnectionManager.circuitResetTimeout = setTimeout(() => {
          logger.info('Redis circuit breaker reset, attempting to reconnect');
          RedisConnectionManager.circuitOpen = false;
          RedisConnectionManager.connectionFailures = 0;
        }, RedisConnectionManager.CIRCUIT_RESET_TIMEOUT);
      }
    }
  }

  /**
   * Start periodic health check
   */
  private static startHealthCheck(): void {
    if (RedisConnectionManager.healthCheckInterval) {
      clearInterval(RedisConnectionManager.healthCheckInterval);
    }

    // Check health every 30 seconds
    RedisConnectionManager.healthCheckInterval = setInterval(async () => {
      try {
        if (RedisConnectionManager.isInitialized && !RedisConnectionManager.circuitOpen) {
          const status = await RedisConnectionManager.healthCheck();
          if (status.status !== 'ok') {
            logger.warn('Redis health check failed', { details: status.details });
          }
        }
      } catch (error) {
        logger.error('Error during Redis health check', { error });
      }
    }, 30000);
  }

  /**
   * Connect to Redis
   */
  public static async connect(): Promise<void> {
    if (RedisConnectionManager.isInitialized) {
      logger.debug('Redis client already connected');
      return;
    }

    try {
      const client = RedisConnectionManager.getInstance();
      await client.connect();
      RedisConnectionManager.isInitialized = true;
      logger.info('Redis connection established successfully');
    } catch (error) {
      logger.error('Failed to connect to Redis', { error });
      RedisConnectionManager.handleConnectionFailure();
      throw new DatabaseError(
        'Failed to connect to Redis',
        'REDIS_CONNECTION_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Disconnect from Redis
   */
  public static async disconnect(): Promise<void> {
    if (!RedisConnectionManager.isInitialized || !RedisConnectionManager.instance) {
      return;
    }

    try {
      // Clear health check interval
      if (RedisConnectionManager.healthCheckInterval) {
        clearInterval(RedisConnectionManager.healthCheckInterval);
        RedisConnectionManager.healthCheckInterval = null;
      }

      // Clear circuit breaker timeout
      if (RedisConnectionManager.circuitResetTimeout) {
        clearTimeout(RedisConnectionManager.circuitResetTimeout);
        RedisConnectionManager.circuitResetTimeout = null;
      }

      // Disconnect all subscribers
      for (const [channel, subscriber] of RedisConnectionManager.subscribers) {
        await subscriber.quit();
        RedisConnectionManager.subscribers.delete(channel);
      }

      // Disconnect main client
      await RedisConnectionManager.instance.quit();
      RedisConnectionManager.isInitialized = false;
      RedisConnectionManager.instance = null as any;
      logger.info('Redis connection closed');
    } catch (error) {
      logger.error('Error closing Redis connection', { error });
      throw new DatabaseError(
        'Error closing Redis connection',
        'REDIS_DISCONNECT_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Get a subscriber client for a specific channel
   * @param channel The channel to subscribe to
   * @returns A Redis client subscribed to the channel
   */
  public static async getSubscriber(channel: string): Promise<TypedRedisClient> {
    if (RedisConnectionManager.subscribers.has(channel)) {
      return RedisConnectionManager.subscribers.get(channel)!;
    }

    try {
      const subscriber = createClient(redisConfig) as TypedRedisClient;
      await subscriber.connect();

      RedisConnectionManager.subscribers.set(channel, subscriber);
      return subscriber;
    } catch (error) {
      logger.error('Failed to create Redis subscriber', { channel, error });
      throw new DatabaseError(
        'Failed to create Redis subscriber',
        'REDIS_SUBSCRIBER_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check Redis connection status
   * @returns Connection status
   */
  public static async healthCheck(): Promise<{ status: string; details?: string }> {
    if (RedisConnectionManager.circuitOpen) {
      return {
        status: 'error',
        details: 'Redis circuit breaker is open due to multiple connection failures',
      };
    }

    try {
      const client = RedisConnectionManager.getInstance();

      if (!client.isOpen) {
        return {
          status: 'error',
          details: 'Redis client is not connected',
        };
      }

      const ping = await client.ping();

      return {
        status: ping === 'PONG' ? 'ok' : 'error',
        details: `Connected to Redis at ${databaseConfig.redis?.host || 'localhost'}:${databaseConfig.redis?.port || 6379}`,
      };
    } catch (error) {
      logger.error('Redis health check failed', { error });
      return {
        status: 'error',
        details: `Failed to connect to Redis: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /**
   * Check if Redis is connected
   * @returns True if connected, false otherwise
   */
  public static isConnected(): boolean {
    return (
      RedisConnectionManager.isInitialized &&
      RedisConnectionManager.instance?.isOpen &&
      !RedisConnectionManager.circuitOpen
    );
  }
}

/**
 * Cache operations with layered caching strategy
 */
export class RedisCache {
  private static readonly DEFAULT_TTL = 3600; // 1 hour in seconds
  private static readonly MEMORY_CACHE = new Map<string, { value: any; expiry: number }>();
  private static readonly MEMORY_CACHE_TTL = 60; // 1 minute in seconds

  /**
   * Get the key prefix from config or default to empty string
   * @returns The key prefix as a string
   */
  private static getKeyPrefix(): string {
    // Ensure we always return a string, even if redis config is undefined
    if (!databaseConfig.redis || typeof databaseConfig.redis.keyPrefix !== 'string') {
      return '';
    }
    return databaseConfig.redis.keyPrefix;
  }

  /**
   * Set a value in the cache
   * @param key The cache key
   * @param value The value to cache
   * @param ttl Time to live in seconds (optional)
   */
  public static async set(key: string, value: any, ttl?: number): Promise<void> {
    const keyPrefix = RedisCache.getKeyPrefix();
    const prefixedKey = `${keyPrefix}${key}`;
    const serializedValue = JSON.stringify(value);

    try {
      const client = RedisConnectionManager.getInstance();

      // Set in Redis
      if (ttl) {
        await client.set(prefixedKey, serializedValue, { EX: ttl });
      } else {
        // Use DEFAULT_TTL when no ttl is provided
        await client.set(prefixedKey, serializedValue, { EX: RedisCache.DEFAULT_TTL });
      }

      // Set in memory cache
      RedisCache.MEMORY_CACHE.set(prefixedKey, {
        value,
        expiry: Date.now() + RedisCache.MEMORY_CACHE_TTL * 1000,
      });

      // Log cache metrics
      logger.debug('Cache set', { key: prefixedKey, size: serializedValue.length });
    } catch (error) {
      logger.error('Failed to set cache key', { key: prefixedKey, error });
      throw new DatabaseError(
        'Failed to set cache key',
        'REDIS_CACHE_SET_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Get a value from the cache
   * @param key The cache key
   * @returns The cached value or null if not found
   */
  public static async get<T = any>(key: string): Promise<T | null> {
    const keyPrefix = RedisCache.getKeyPrefix();
    const prefixedKey = `${keyPrefix}${key}`;

    try {
      // Check memory cache first (L1)
      const memoryCache = RedisCache.MEMORY_CACHE.get(prefixedKey);
      if (memoryCache && memoryCache.expiry > Date.now()) {
        logger.debug('Cache hit (memory)', { key: prefixedKey });
        return memoryCache.value as T;
      }

      // Check Redis (L2)
      const client = RedisConnectionManager.getInstance();
      const value = await client.get(prefixedKey);

      if (value) {
        logger.debug('Cache hit (Redis)', { key: prefixedKey });
        const parsed = JSON.parse(value) as T;

        // Update memory cache
        RedisCache.MEMORY_CACHE.set(prefixedKey, {
          value: parsed,
          expiry: Date.now() + RedisCache.MEMORY_CACHE_TTL * 1000,
        });

        return parsed;
      }

      logger.debug('Cache miss', { key: prefixedKey });
      return null;
    } catch (error) {
      logger.error('Failed to get cache key', { key: prefixedKey, error });
      // Don't throw error on cache miss, just return null
      return null;
    }
  }

  /**
   * Delete a key from the cache
   * @param key The cache key
   * @returns Number of keys removed
   */
  public static async delete(key: string): Promise<number> {
    const keyPrefix = RedisCache.getKeyPrefix();
    const prefixedKey = `${keyPrefix}${key}`;

    try {
      // Remove from memory cache
      RedisCache.MEMORY_CACHE.delete(prefixedKey);

      // Remove from Redis
      const client = RedisConnectionManager.getInstance();
      return await client.del(prefixedKey);
    } catch (error) {
      logger.error('Failed to delete cache key', { key: prefixedKey, error });
      throw new DatabaseError(
        'Failed to delete cache key',
        'REDIS_CACHE_DELETE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Check if a key exists in the cache
   * @param key The cache key
   * @returns True if the key exists, false otherwise
   */
  public static async exists(key: string): Promise<boolean> {
    const keyPrefix = RedisCache.getKeyPrefix();
    const prefixedKey = `${keyPrefix}${key}`;

    try {
      // Check memory cache first
      const memoryCache = RedisCache.MEMORY_CACHE.get(prefixedKey);
      if (memoryCache && memoryCache.expiry > Date.now()) {
        return true;
      }

      // Check Redis
      const client = RedisConnectionManager.getInstance();
      return (await client.exists(prefixedKey)) === 1;
    } catch (error) {
      logger.error('Failed to check cache key existence', { key: prefixedKey, error });
      throw new DatabaseError(
        'Failed to check cache key existence',
        'REDIS_CACHE_EXISTS_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Get multiple values from the cache
   * @param keys The cache keys
   * @returns Object with keys and values
   */
  public static async mget<T = any>(keys: string[]): Promise<Record<string, T | null>> {
    const keyPrefix = RedisCache.getKeyPrefix();
    const prefixedKeys = keys.map(key => `${keyPrefix}${key}`);
    const result: Record<string, T | null> = {};

    try {
      // Initialize result with null values
      keys.forEach(key => {
        result[key] = null;
      });

      // Check memory cache first
      const keysToFetch: string[] = [];
      const now = Date.now();

      // Use a traditional for loop instead of forEach for better type safety
      for (let i = 0; i < prefixedKeys.length; i++) {
        const prefixedKey = prefixedKeys[i];
        const originalKey = keys[i];

        // Skip if either key is undefined
        if (!prefixedKey || !originalKey) continue;

        const memoryCache = RedisCache.MEMORY_CACHE.get(prefixedKey);
        if (memoryCache && memoryCache.expiry > now) {
          result[originalKey] = memoryCache.value as T;
        } else {
          keysToFetch.push(prefixedKey);
        }
      }

      // If all keys were found in memory cache, return early
      if (keysToFetch.length === 0) {
        return result;
      }

      // Fetch remaining keys from Redis
      const client = RedisConnectionManager.getInstance();
      const values = await client.mGet(keysToFetch);

      // Process Redis results using a for loop instead of forEach to properly handle continue statements
      for (let i = 0; i < values.length; i++) {
        const value = values[i];
        if (!value) continue;

        // Find the original key by matching the prefixed key
        const prefixedKey = keysToFetch[i];
        if (!prefixedKey) continue; // Skip if prefixedKey is undefined

        const originalKeyIndex = prefixedKeys.indexOf(prefixedKey);
        if (originalKeyIndex === -1) continue;

        const originalKey = keys[originalKeyIndex];
        if (!originalKey) continue; // Skip if originalKey is undefined

        try {
          const parsed = JSON.parse(value) as T;
          result[originalKey] = parsed;

          // Update memory cache
          RedisCache.MEMORY_CACHE.set(prefixedKey, {
            value: parsed,
            expiry: now + RedisCache.MEMORY_CACHE_TTL * 1000,
          });
        } catch (error) {
          logger.error('Failed to parse cache value', { error });
        }
      }

      return result;
    } catch (error) {
      logger.error('Failed to get multiple cache keys', { keys, error });
      // Return whatever we have
      return result;
    }
  }

  /**
   * Set multiple values in the cache
   * @param entries Object with keys and values
   * @param ttl Time to live in seconds (optional)
   */
  public static async mset(entries: Record<string, any>, ttl?: number): Promise<void> {
    try {
      const client = RedisConnectionManager.getInstance();
      const now = Date.now();
      const pipeline = client.multi();
      const keyPrefix = RedisCache.getKeyPrefix();

      // Process each entry
      for (const [key, value] of Object.entries(entries)) {
        const prefixedKey = `${keyPrefix}${key}`;
        const serializedValue = JSON.stringify(value);

        // Add to Redis pipeline
        if (ttl) {
          pipeline.set(prefixedKey, serializedValue, { EX: ttl });
        } else {
          // Use DEFAULT_TTL when no ttl is provided, for consistency with set method
          pipeline.set(prefixedKey, serializedValue, { EX: RedisCache.DEFAULT_TTL });
        }

        // Update memory cache
        RedisCache.MEMORY_CACHE.set(prefixedKey, {
          value,
          expiry: now + RedisCache.MEMORY_CACHE_TTL * 1000,
        });
      }

      // Execute pipeline
      await pipeline.exec();
    } catch (error) {
      logger.error('Failed to set multiple cache keys', { error });
      throw new DatabaseError(
        'Failed to set multiple cache keys',
        'REDIS_CACHE_MSET_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Increment a counter in the cache
   * @param key The cache key
   * @param increment The increment value (default: 1)
   * @returns The new value
   */
  public static async increment(key: string, increment = 1): Promise<number> {
    const keyPrefix = RedisCache.getKeyPrefix();
    const prefixedKey = `${keyPrefix}${key}`;

    try {
      const client = RedisConnectionManager.getInstance();
      const value = await client.incrBy(prefixedKey, increment);

      // Update memory cache
      RedisCache.MEMORY_CACHE.set(prefixedKey, {
        value,
        expiry: Date.now() + RedisCache.MEMORY_CACHE_TTL * 1000,
      });

      return value;
    } catch (error) {
      logger.error('Failed to increment cache key', { key: prefixedKey, error });
      throw new DatabaseError(
        'Failed to increment cache key',
        'REDIS_CACHE_INCREMENT_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Publish a message to a channel
   * @param channel The channel name
   * @param message The message to publish
   * @returns Number of clients that received the message
   */
  public static async publish(channel: string, message: any): Promise<number> {
    try {
      const client = RedisConnectionManager.getInstance();
      const serializedMessage = typeof message === 'string' ? message : JSON.stringify(message);
      return await client.publish(channel, serializedMessage);
    } catch (error) {
      logger.error('Failed to publish message', { channel, error });
      throw new DatabaseError(
        'Failed to publish message',
        'REDIS_PUBLISH_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Subscribe to a channel
   * @param channel The channel name
   * @param callback The callback function to execute when a message is received
   */
  public static async subscribe(
    channel: string,
    callback: (message: string, channel: string) => void
  ): Promise<void> {
    try {
      const subscriber = await RedisConnectionManager.getSubscriber(channel);
      await subscriber.subscribe(channel, (message, channelName) => {
        // Ensure message is always a string
        const messageStr = typeof message === 'string' ? message : String(message);
        callback(messageStr, channelName);
      });

      logger.debug('Subscribed to channel', { channel });
    } catch (error) {
      logger.error('Failed to subscribe to channel', { channel, error });
      throw new DatabaseError(
        'Failed to subscribe to channel',
        'REDIS_SUBSCRIBE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Unsubscribe from a channel
   * @param channel The channel name
   */
  public static async unsubscribe(channel: string): Promise<void> {
    try {
      // Ensure channel is a string before using it as a Map key
      if (typeof channel === 'string' && RedisConnectionManager['subscribers'].has(channel)) {
        const subscriber = RedisConnectionManager['subscribers'].get(channel);
        if (subscriber) {
          await subscriber.unsubscribe(channel);
          logger.debug('Unsubscribed from channel', { channel });
        }
      }
    } catch (error) {
      logger.error('Failed to unsubscribe from channel', { channel, error });
      throw new DatabaseError(
        'Failed to unsubscribe from channel',
        'REDIS_UNSUBSCRIBE_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Clear the memory cache
   */
  public static clearMemoryCache(): void {
    RedisCache.MEMORY_CACHE.clear();
    logger.debug('Memory cache cleared');
  }
}

// Export connection methods
export const connectRedis = RedisConnectionManager.connect;
export const disconnectRedis = RedisConnectionManager.disconnect;
export const getRedisStatus = RedisConnectionManager.healthCheck;
export const isRedisConnected = RedisConnectionManager.isConnected;

/**
 * Get the Redis client instance
 * @returns The Redis client instance
 * @throws Error if Redis is not connected
 */
export function getRedisClient(): TypedRedisClient {
  return RedisConnectionManager.getInstance();
}

// Export cache methods
export const redisCache = RedisCache;

// Export RedisConnectionManager for metrics collector
export { RedisConnectionManager };
