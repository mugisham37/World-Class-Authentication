// Type definitions for the database optimizer service
export interface PerformanceConfig {
  database: {
    query: {
      logging: boolean;
      caching: boolean;
      timeout: number;
      slowQueryThreshold: number;
      cacheTtl: number;
    };
  };
}

// Note: PrismaMiddlewareParams and PrismaMiddlewareNext types have been removed
// as we now use the official Prisma types directly from @prisma/client

export interface QueryStats {
  count: number;
  totalTime: number;
  avgTime: number;
}

export interface SlowQuery {
  query: string;
  duration: number;
  timestamp: Date;
}

export interface CacheEntry {
  data: any;
  expiry: number;
}

export interface OptimizeQueryOptions {
  cacheKey?: string;
  cacheTtl?: number;
  timeout?: number;
  retries?: number;
  retryDelay?: number;
}
