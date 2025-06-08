const cluster = require('cluster');
const os = require('os');
const { App } = require('./app');
const { logger } = require('./infrastructure/logging/logger');
const { appConfig } = require('./config/app-config');
const { env } = require('./config/environment');
const { shutdownDataLayer, connectionMonitor } = require('./data');
const { metricsCollector } = require('./data/connections/metrics-collector');

/**
 * Start the server
 * Initializes the application and starts the HTTP server
 */
async function startServer() {
  try {
    logger.info(`Starting server in ${env.getEnvironment()} mode`);

    // Initialize the application
    const app = new App();
    await app.initialize();

    // Start the HTTP server
    const server = app.app.listen(appConfig.app.port, () => {
      logger.info(`Server started on port ${appConfig.app.port}`);
      logger.info(`Health check: http://localhost:${appConfig.app.port}/health`);
      logger.info(`API base URL: http://localhost:${appConfig.app.port}${appConfig.app.apiPrefix}`);
    });

    // Start metrics collection
    startMetricsCollection();

    // Set up connection monitoring
    setupConnectionMonitoring();

    // Handle graceful shutdown
    setupGracefulShutdown(server);

    // Handle uncaught exceptions and unhandled rejections
    setupProcessErrorHandlers();

    return server;
  } catch (error) {
    logger.error('Failed to start server', { error });
    process.exit(1);
  }
}

/**
 * Start metrics collection
 * Collects metrics about the application and database connections
 */
function startMetricsCollection() {
  try {
    // Set up initial metrics
    // Set up process metrics
    if (env.getBoolean('METRICS_PROCESS_ENABLED', true) ?? true) {
      // Track process memory usage
      const memoryUsage = process.memoryUsage();
      metricsCollector.setGauge('process.memory.rss', memoryUsage.rss);
      metricsCollector.setGauge('process.memory.heapTotal', memoryUsage.heapTotal);
      metricsCollector.setGauge('process.memory.heapUsed', memoryUsage.heapUsed);
      metricsCollector.setGauge('process.memory.external', memoryUsage.external);
    }

    // Start collecting metrics
    metricsCollector.startCollecting();
    logger.info('Metrics collection started');
  } catch (error) {
    logger.error('Failed to start metrics collection', { error });
  }
}

/**
 * Set up connection monitoring
 * Monitors database connections and logs events
 */
function setupConnectionMonitoring() {
  // Listen for health change events
  connectionMonitor.on('health-change', (service: string, health: any, previousHealth: any) => {
    if (health.status === 'error') {
      logger.warn(
        `${service} connection health changed from ${previousHealth.status} to ${health.status}`,
        {
          service,
          details: health.details,
        }
      );
    } else if (health.status === 'ok' && previousHealth.status !== 'ok') {
      logger.info(
        `${service} connection health recovered from ${previousHealth.status} to ${health.status}`,
        {
          service,
        }
      );
    }
  });

  // Listen for connection error events
  connectionMonitor.on('connection-error', (service: string, error: any) => {
    logger.error(`${service} connection error`, {
      service,
      error,
    });
  });

  // Listen for connection recovery events
  connectionMonitor.on('connection-recovery', (service: string) => {
    logger.info(`${service} connection recovered`, {
      service,
    });
  });

  logger.info('Connection monitoring set up');
}

/**
 * Set up graceful shutdown
 * Handles SIGTERM and SIGINT signals
 * @param server HTTP server instance
 */
function setupGracefulShutdown(server: any) {
  const gracefulShutdown = async (signal: string) => {
    logger.info(`${signal} received. Shutting down gracefully...`);

    // Create a shutdown timeout
    const shutdownTimeout = setTimeout(
      () => {
        logger.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
      },
      env.getNumber('SHUTDOWN_TIMEOUT', 30000) || 30000
    ); // 30 seconds

    try {
      // Stop metrics collection
      metricsCollector.stopCollecting();
      logger.info('Metrics collection stopped');

      // Close HTTP server (stop accepting new connections)
      await new Promise<void>((resolve, reject) => {
        server.close((err: any) => {
          if (err) {
            logger.error('Error closing HTTP server', { error: err });
            reject(err);
          } else {
            logger.info('HTTP server closed');
            resolve();
          }
        });
      });

      // Shutdown data layer (close database connections)
      await shutdownDataLayer();
      logger.info('Database connections closed');

      // Clear the shutdown timeout
      clearTimeout(shutdownTimeout);

      // Exit gracefully
      logger.info('Graceful shutdown completed');
      process.exit(0);
    } catch (error) {
      logger.error('Error during shutdown', { error });
      clearTimeout(shutdownTimeout);
      process.exit(1);
    }
  };

  // Register signal handlers
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  logger.info('Graceful shutdown handlers registered');
}

/**
 * Set up process error handlers
 * Handles uncaught exceptions and unhandled rejections
 */
function setupProcessErrorHandlers() {
  // Handle uncaught exceptions
  process.on('uncaughtException', error => {
    logger.error('Uncaught exception', { error });
    // Exit the process after logging
    // This is a serious error, so we should exit and let the process manager restart the app
    process.exit(1);
  });

  // Handle unhandled rejections
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled rejection', { reason, promise });
    // We don't exit the process for unhandled rejections
    // But we should log them to investigate
  });

  logger.info('Process error handlers registered');
}

/**
 * Check if cluster mode is enabled
 * @returns True if cluster mode is enabled
 */
function isClusterModeEnabled(): boolean {
  return env.getBoolean('CLUSTER_MODE_ENABLED', false) ?? false;
}

/**
 * Get the number of worker processes to spawn
 * @returns Number of worker processes
 */
function getWorkerCount(): number {
  const configuredWorkers = env.getNumber('CLUSTER_WORKERS', 0) || 0;
  const cpuCount = os.cpus().length;

  // If configured workers is 0 or not specified, use CPU count
  // Otherwise use the configured value
  return configuredWorkers > 0 ? configuredWorkers : cpuCount;
}

// Start the server
if (cluster.isPrimary && isClusterModeEnabled()) {
  const numWorkers = getWorkerCount();

  logger.info(`Starting server in cluster mode with ${numWorkers} workers`);

  // Fork workers
  for (let i = 0; i < numWorkers; i++) {
    cluster.fork();
  }

  // Handle worker exit
  cluster.on('exit', (worker: any, code: any, signal: any) => {
    logger.warn(`Worker ${worker.process.pid} died with code ${code} and signal ${signal}`);
    // Replace the dead worker
    logger.info('Starting a new worker');
    cluster.fork();
  });
} else {
  // Start the server in single process mode
  startServer();
}

// Export for testing
export { startServer };
