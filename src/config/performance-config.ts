import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();

// Define performance config schema with Zod
const performanceConfigSchema = z.object({
  cache: z.object({
    defaultTtl: z.number().int().positive().default(3600), // 1 hour
    localCacheMaxSize: z.number().int().positive().default(1000),
    levels: z.object({
      l1: z.object({
        enabled: z.boolean().default(true),
        ttl: z.number().int().positive().default(60), // 1 minute
      }),
      l2: z.object({
        enabled: z.boolean().default(true),
        ttl: z.number().int().positive().default(3600), // 1 hour
      }),
    }),
    prefixes: z.object({
      user: z.string().default('user'),
      session: z.string().default('session'),
      token: z.string().default('token'),
      config: z.string().default('config'),
      mfa: z.string().default('mfa'),
      recovery: z.string().default('recovery'),
      oauth: z.string().default('oauth'),
      saml: z.string().default('saml'),
      metrics: z.string().default('metrics'),
    }),
  }),
  database: z.object({
    pool: z.object({
      min: z.number().int().nonnegative().default(2),
      max: z.number().int().positive().default(10),
      idle: z.number().int().positive().default(10000), // 10 seconds
      acquire: z.number().int().positive().default(30000), // 30 seconds
    }),
    query: z.object({
      logging: z.boolean().default(false),
      caching: z.boolean().default(true),
      timeout: z.number().int().positive().default(5000), // 5 seconds
      slowQueryThreshold: z.number().int().positive().default(1000), // 1 second
      cacheTtl: z.number().int().positive().default(300), // 5 minutes
    }),
  }),
  rateLimiting: z.object({
    enabled: z.boolean().default(true),
    windowMs: z.number().int().positive().default(60000), // 1 minute
    max: z.number().int().positive().default(100),
    headers: z.boolean().default(true),
    keyGenerator: z.enum(['ip', 'user', 'custom']).default('ip'),
    storage: z.enum(['memory', 'redis']).default('redis'),
  }),
  compression: z.object({
    enabled: z.boolean().default(true),
    level: z.number().int().min(0).max(9).default(6),
    threshold: z.number().int().positive().default(1024), // 1 KB
  }),
  monitoring: z.object({
    enabled: z.boolean().default(true),
    interval: z.number().int().positive().default(60000), // 1 minute
    requestLogging: z.boolean().default(true),
    responseLogging: z.boolean().default(false),
    errorLogging: z.boolean().default(true),
    metricsCollection: z.boolean().default(true),
    healthCheck: z.boolean().default(true),
    slowRequestThreshold: z.number().int().positive().default(1000), // 1 second
  }),
});

// Parse and validate environment variables
const rawConfig = {
  cache: {
    defaultTtl: env.getNumber('PERF_CACHE_DEFAULT_TTL'),
    localCacheMaxSize: env.getNumber('PERF_CACHE_LOCAL_MAX_SIZE'),
    levels: {
      l1: {
        enabled: env.getBoolean('PERF_CACHE_L1_ENABLED'),
        ttl: env.getNumber('PERF_CACHE_L1_TTL'),
      },
      l2: {
        enabled: env.getBoolean('PERF_CACHE_L2_ENABLED'),
        ttl: env.getNumber('PERF_CACHE_L2_TTL'),
      },
    },
    prefixes: {
      user: env.get('PERF_CACHE_PREFIX_USER'),
      session: env.get('PERF_CACHE_PREFIX_SESSION'),
      token: env.get('PERF_CACHE_PREFIX_TOKEN'),
      config: env.get('PERF_CACHE_PREFIX_CONFIG'),
      mfa: env.get('PERF_CACHE_PREFIX_MFA'),
      recovery: env.get('PERF_CACHE_PREFIX_RECOVERY'),
      oauth: env.get('PERF_CACHE_PREFIX_OAUTH'),
      saml: env.get('PERF_CACHE_PREFIX_SAML'),
      metrics: env.get('PERF_CACHE_PREFIX_METRICS'),
    },
  },
  database: {
    pool: {
      min: env.getNumber('PERF_DB_POOL_MIN'),
      max: env.getNumber('PERF_DB_POOL_MAX'),
      idle: env.getNumber('PERF_DB_POOL_IDLE'),
      acquire: env.getNumber('PERF_DB_POOL_ACQUIRE'),
    },
    query: {
      logging: env.getBoolean('PERF_DB_QUERY_LOGGING'),
      caching: env.getBoolean('PERF_DB_QUERY_CACHING'),
      timeout: env.getNumber('PERF_DB_QUERY_TIMEOUT'),
      slowQueryThreshold: env.getNumber('PERF_DB_QUERY_SLOW_THRESHOLD'),
      cacheTtl: env.getNumber('PERF_DB_QUERY_CACHE_TTL'),
    },
  },
  rateLimiting: {
    enabled: env.getBoolean('PERF_RATE_LIMIT_ENABLED'),
    windowMs: env.getNumber('PERF_RATE_LIMIT_WINDOW_MS'),
    max: env.getNumber('PERF_RATE_LIMIT_MAX'),
    headers: env.getBoolean('PERF_RATE_LIMIT_HEADERS'),
    keyGenerator: env.get('PERF_RATE_LIMIT_KEY_GENERATOR') as 'ip' | 'user' | 'custom',
    storage: env.get('PERF_RATE_LIMIT_STORAGE') as 'memory' | 'redis',
  },
  compression: {
    enabled: env.getBoolean('PERF_COMPRESSION_ENABLED'),
    level: env.getNumber('PERF_COMPRESSION_LEVEL'),
    threshold: env.getNumber('PERF_COMPRESSION_THRESHOLD'),
  },
  monitoring: {
    enabled: env.getBoolean('PERF_MONITORING_ENABLED'),
    interval: env.getNumber('PERF_MONITORING_INTERVAL'),
    requestLogging: env.getBoolean('PERF_MONITORING_REQUEST_LOGGING'),
    responseLogging: env.getBoolean('PERF_MONITORING_RESPONSE_LOGGING'),
    errorLogging: env.getBoolean('PERF_MONITORING_ERROR_LOGGING'),
    metricsCollection: env.getBoolean('PERF_MONITORING_METRICS_COLLECTION'),
    healthCheck: env.getBoolean('PERF_MONITORING_HEALTH_CHECK'),
    slowRequestThreshold: env.getNumber('PERF_MONITORING_SLOW_REQUEST_THRESHOLD'),
  },
};

// Validate and export config
export const performanceConfig = validateConfig(performanceConfigSchema, rawConfig);

// Export config type
export type PerformanceConfig = typeof performanceConfig;
