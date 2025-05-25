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

export interface PrismaMiddlewareParams {
  model?: string;
  action: string;
  args: any;
  dataPath: string[];
  runInTransaction: boolean;
}

export type PrismaMiddlewareNext = (params: PrismaMiddlewareParams) => Promise<any>;

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
