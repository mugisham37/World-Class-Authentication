import app from './app';
import { env } from './config/environment';
import { initializeDataLayer, shutdownDataLayer, checkDataLayerHealth } from './data';
import { logger } from './infrastructure/logging/logger';
import { connectionMonitor } from './data/connections/connection-monitor';
import { metricsCollector } from './data/connections/metrics-collector';

// Get port from environment
const PORT = env.getNumber('PORT') || 3000;

// Start server
const server = app.listen(PORT, async () => {
  logger.info(`Server running on port ${PORT} in ${env.getEnvironment()} mode`);
  logger.info(`Health check: http://localhost:${PORT}/health`);
  logger.info(`API base URL: http://localhost:${PORT}/api/${env.get('API_VERSION')}`);

  // Initialize data layer
  await initializeDatabase();
});

// Initialize database connections
async function initializeDatabase() {
  try {
    // Initialize data layer
    await initializeDataLayer();
    logger.info('Database connections initialized successfully');

    // Check database health
    const health = await checkDataLayerHealth();
    logger.info('Database health check', { health });

    // Set up connection monitoring events
    setupConnectionMonitoring();
  } catch (error) {
    logger.error('Failed to initialize database connections', { error });
    process.exit(1);
  }
}

// Set up connection monitoring events
function setupConnectionMonitoring() {
  // Listen for health change events
  connectionMonitor.on('health-change', (service, health, previousHealth) => {
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
  connectionMonitor.on('connection-error', (service, error) => {
    logger.error(`${service} connection error`, {
      service,
      error,
    });
  });

  // Listen for connection recovery events
  connectionMonitor.on('connection-recovery', service => {
    logger.info(`${service} connection recovered`, {
      service,
    });
  });
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  await gracefulShutdown();
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, shutting down gracefully');
  await gracefulShutdown();
});

async function gracefulShutdown() {
  try {
    // Close server
    server.close(() => {
      logger.info('Server closed');
    });

    // Shutdown data layer
    await shutdownDataLayer();
    logger.info('Database connections closed');

    // Stop metrics collection
    metricsCollector.stopCollecting();
    logger.info('Metrics collection stopped');

    process.exit(0);
  } catch (error) {
    logger.error('Error during shutdown', { error });
    process.exit(1);
  }
}

export default server;
