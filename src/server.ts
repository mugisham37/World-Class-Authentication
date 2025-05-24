import app from './app';
import { env } from './config/environment';
import { initializeDataLayer, shutdownDataLayer, checkDataLayerHealth } from './data';
import { logger } from './infrastructure/logging/logger';

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
    await initializeDataLayer();
    logger.info('Database connections initialized successfully');

    // Check database health
    const health = await checkDataLayerHealth();
    logger.info('Database health check', { health });
  } catch (error) {
    logger.error('Failed to initialize database connections', { error });
    process.exit(1);
  }
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

    process.exit(0);
  } catch (error) {
    logger.error('Error during shutdown', { error });
    process.exit(1);
  }
}

export default server;
