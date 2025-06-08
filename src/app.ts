const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const { Container } = require('@tsed/di');
const { apiRouter } = require('./api/routes');
const { initializeDataLayer } = require('./data');
const { errorHandler, notFoundHandler } = require('./api/middlewares/error-handling.middleware');
const { correlationIdMiddleware } = require('./api/middlewares/correlation-id.middleware');
const { requestLogger } = require('./api/middlewares/request-logger.middleware');
const { securityHeaders } = require('./api/middlewares/security-headers.middleware');
const { defaultRateLimiter } = require('./api/middlewares/rate-limiting.middleware');
const { deviceFingerprint } = require('./api/middlewares/device-fingerprint.middleware');
const { appConfig } = require('./config/app-config');
const { logger } = require('./infrastructure/logging/logger');
const { env } = require('./config/environment');
const { metricsCollector } = require('./data/connections/metrics-collector');

// Type definitions
type Request = any;
type Response = any;
type NextFunction = any;
type Application = any;

// Define interface for request with container
interface RequestWithContainer extends Request {
  container?: typeof Container;
  user?: {
    id: string;
    email: string;
    sessionId: string;
  };
}

/**
 * Main application class
 * Handles Express application setup, middleware configuration, and initialization
 */
export class App {
  public app: Application;
  private container: typeof Container;

  /**
   * Constructor
   * Creates Express application and dependency injection container
   */
  constructor() {
    this.app = express();
    this.container = new Container();
  }

  /**
   * Initialize the application
   * Sets up middleware, routes, error handling, and database connections
   */
  public async initialize(): Promise<void> {
    try {
      // Initialize container
      await this.initializeContainer();

      // Connect to databases
      await initializeDataLayer();

      // Configure middleware
      this.configureMiddleware();

      // Configure routes
      this.configureRoutes();

      // Configure error handling
      this.configureErrorHandling();

      // Configure health checks
      this.configureHealthChecks();

      // Schedule cleanup tasks
      this.scheduleCleanupTasks();

      logger.info('Application initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize application', { error });
      throw error;
    }
  }

  /**
   * Initialize dependency injection container
   */
  private async initializeContainer(): Promise<void> {
    try {
      // Set up container
      this.app.use((req: RequestWithContainer, _res: Response, next: NextFunction) => {
        req.container = this.container;
        next();
      });

      // Register services in the container
      // Note: This is a placeholder for your actual DI setup
      // Typically you would register your services here
      // For example: this.container.register(ServiceClass)

      logger.info('Container initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize container', { error });
      throw error;
    }
  }

  /**
   * Configure middleware
   * Sets up middleware in the correct order
   */
  private configureMiddleware(): void {
    // Security headers
    this.app.use(helmet());
    this.app.use(securityHeaders);

    // CORS
    this.app.use(
      cors({
        origin: appConfig.cors.origin,
        methods: appConfig.cors.methods,
        allowedHeaders: appConfig.cors.allowedHeaders,
        exposedHeaders: appConfig.cors.exposedHeaders,
        credentials: appConfig.cors.credentials,
        maxAge: appConfig.cors.maxAge,
      })
    );

    // Request parsing
    this.app.use(express.json({ limit: '1mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '1mb' }));

    // Cookie parser - dynamically import to avoid module not found errors
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const cookieParser = require('cookie-parser');
      this.app.use(cookieParser());
    } catch (error) {
      logger.warn('Cookie parser not available, skipping', { error });
    }

    // Compression
    this.app.use(compression());

    // Request tracking
    this.app.use(correlationIdMiddleware);
    this.app.use(requestLogger);

    // Device fingerprinting
    this.app.use(deviceFingerprint);

    // Rate limiting
    this.app.use(defaultRateLimiter);

    // Metrics collection middleware
    this.configureMetrics();

    logger.info('Middleware configured successfully');
  }

  /**
   * Configure routes
   * Sets up API routes
   */
  private configureRoutes(): void {
    // API routes
    this.app.use(appConfig.app.apiPrefix, apiRouter);

    logger.info('Routes configured successfully');
  }

  /**
   * Configure metrics collection middleware
   * Sets up middleware to collect metrics about requests and responses
   */
  private configureMetrics(): void {
    // Track request metrics
    this.app.use((req: Request, res: Response, next: NextFunction) => {
      const startTime = Date.now();

      // Track response metrics
      res.on('finish', () => {
        const duration = Date.now() - startTime;
        const statusCode = res.statusCode;

        // Track request duration
        metricsCollector.observeHistogram('http.request.duration', duration);

        // Track status codes
        metricsCollector.incrementCounter(`http.response.status.${Math.floor(statusCode / 100)}xx`);

        // Track specific endpoints (optional)
        if (req.path) {
          // Normalize path to avoid high cardinality
          const normalizedPath = req.path.replace(/\/[0-9a-f]{24}|\/\d+/g, '/:id');
          metricsCollector.observeHistogram(
            `http.request.${req.method}.${normalizedPath}.duration`,
            duration
          );
        }
      });

      next();
    });

    logger.info('Metrics collection configured successfully');
  }

  /**
   * Configure error handling
   * Sets up 404 handler and global error handler
   */
  private configureErrorHandling(): void {
    // 404 handler
    this.app.use(notFoundHandler);

    // Global error handler
    this.app.use(errorHandler);

    logger.info('Error handling configured successfully');
  }

  /**
   * Configure health checks
   * Sets up health check endpoints
   */
  private configureHealthChecks(): void {
    // Basic health check endpoint
    this.app.get('/health', (_req: Request, res: Response) => {
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        environment: env.getEnvironment(),
        version: process.env['npm_package_version'] || 'unknown',
      });
    });

    // Readiness check endpoint
    this.app.get('/ready', async (_req: Request, res: Response) => {
      try {
        // Perform health checks
        const checks = await this.performReadinessChecks();
        const isHealthy = checks.every(check => check.status === 'healthy');

        res.status(isHealthy ? 200 : 503).json({
          status: isHealthy ? 'ready' : 'not ready',
          timestamp: new Date().toISOString(),
          checks,
        });
      } catch (error) {
        logger.error('Readiness check failed', { error });
        res.status(503).json({
          status: 'not ready',
          timestamp: new Date().toISOString(),
          error: 'Failed to perform readiness checks',
        });
      }
    });

    logger.info('Health checks configured successfully');
  }

  /**
   * Perform readiness checks
   * @returns Array of check results
   */
  private async performReadinessChecks(): Promise<
    Array<{ name: string; status: string; details?: string }>
  > {
    const checks = [];

    try {
      // Check database connections
      const dbHealth = await import('./data').then(data => data.checkDataLayerHealth());

      checks.push({
        name: 'database',
        status: dbHealth.status === 'ok' ? 'healthy' : 'unhealthy',
        details: dbHealth.status !== 'ok' ? JSON.stringify(dbHealth) : undefined,
      });

      // Add more checks as needed (Redis, external services, etc.)
    } catch (error) {
      logger.error('Error performing readiness checks', { error });
      checks.push({
        name: 'database',
        status: 'unhealthy',
        details: error instanceof Error ? error.message : String(error),
      });
    }

    return checks;
  }

  /**
   * Schedule cleanup tasks
   * Sets up periodic tasks to clean up expired data
   */
  private scheduleCleanupTasks(): void {
    // Clean up expired MFA challenges every hour
    setInterval(
      async () => {
        try {
          // Get MFA challenge repository from container
          const mfaChallengeRepository = this.container.get('MfaChallengeRepository');

          if (mfaChallengeRepository) {
            // Use type assertion and bracket notation to access the method
            const repo = mfaChallengeRepository as { [key: string]: any };
            const deletedCount = await repo['deleteExpired']();
            if (deletedCount > 0) {
              logger.info(`Cleaned up ${deletedCount} expired MFA challenges`);
            }
          }
        } catch (error) {
          logger.error('Failed to clean up expired MFA challenges', { error });
        }
      },
      60 * 60 * 1000 // 1 hour
    );

    // Add more cleanup tasks as needed

    logger.info('Cleanup tasks scheduled successfully');
  }
}
