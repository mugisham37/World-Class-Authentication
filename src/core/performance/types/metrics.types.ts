// Type definitions for the performance monitoring system
export interface SystemMetricsData {
  timestamp: Date;
  cpu: {
    usage: string;
    cores: number;
    loadAvg: number[];
    model: string;
  };
  memory: {
    total: string;
    used: string;
    free: string;
    usedPercentage: string;
  };
  http: {
    requests: number;
    success: number;
    error: number;
    successRate: string;
    requestsPerMinute: string;
    avgResponseTime: string;
    slowestPaths: Array<{
      path: string;
      avgResponseTime: string;
      count: number;
    }>;
  };
  system: {
    platform: string;
    arch: string;
    uptime: string;
    hostname: string;
    nodeVersion: string;
  };
  database: Record<string, unknown>;
  cache: CacheMetrics;
  process: {
    pid: number;
    memoryUsage: {
      rss: string;
      heapTotal: string;
      heapUsed: string;
      external: string;
    };
    uptime: string;
  };
  error?: string;
}

export interface CacheMetrics {
  hitRate: string;
  missRate: string;
  size: string;
  keys: number;
  operations: {
    gets: number;
    sets: number;
    deletes: number;
  };
}

export interface HealthStatus {
  status: 'healthy' | 'unhealthy';
  responseTime?: number;
  error?: string;
  details?: Record<string, unknown>;
}

export interface MonitoringConfig {
  enabled: boolean;
  interval: number;
  requestLogging: boolean;
  responseLogging: boolean;
  errorLogging: boolean;
  metricsCollection: boolean;
  healthCheck: boolean;
  slowRequestThreshold: number;
}
