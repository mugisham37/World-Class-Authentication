# Database Connection Layer

This directory contains the database connection layer for the application. It provides a robust, high-performance, and type-safe interface for interacting with the database.

## Architecture

The database connection layer is built on the following principles:

1. **Intelligent Simplicity**: Sophisticated enough to handle enterprise-scale challenges but simple enough that any developer can understand and extend it.
2. **Connection Pooling**: Efficient resource orchestration for database connections.
3. **Layered Caching**: L1 (in-memory), L2 (Redis), L3 (Database) for optimal performance.
4. **Type Safety**: Leveraging TypeScript to catch errors at compile time.
5. **Observability**: Comprehensive metrics, logging, and health monitoring.
6. **Resilience**: Circuit breaker pattern, automatic retry logic, and graceful degradation.

## Components

### Database Manager

The `DatabaseManager` class is responsible for initializing and shutting down all database connections. It also provides health check functionality.

```typescript
import {
  initializeDatabase,
  shutdownDatabase,
  getDatabaseHealth,
} from './connections/database-manager';

// Initialize database connections
await initializeDatabase();

// Check database health
const health = await getDatabaseHealth();

// Shutdown database connections
await shutdownDatabase();
```

### Connection Wrapper

The `ConnectionWrapper` class provides a high-level interface for database operations, combining the query builder with transaction management and connection pooling.

```typescript
import { db } from './connections/connection-wrapper';

// Execute a query
const users = await db.query('SELECT * FROM users WHERE active = $1', [true]);

// Use the query builder
const posts = await db
  .getQueryBuilder()
  .from('posts')
  .where('user_id', '=', userId)
  .orderBy('created_at', 'DESC')
  .limit(10)
  .get();

// Use the cache
await db.getCache().set('user:1', { id: 1, name: 'John' }, 3600);
const user = await db.getCache().get('user:1');

// Execute a transaction
await db.withTransaction(async () => {
  await db.query('INSERT INTO users (name) VALUES ($1)', ['John']);
  await db.query('INSERT INTO profiles (user_id, bio) VALUES ($1, $2)', [1, 'Hello']);
});
```

### Query Builder

The `QueryBuilder` class provides a fluent interface for building SQL queries.

```typescript
import { createQueryBuilder } from './connections/query-builder';

// Create a query builder
const qb = createQueryBuilder();

// Build and execute a query
const users = await qb
  .from('users')
  .select('id', 'name', 'email')
  .where('active', '=', true)
  .orderBy('created_at', 'DESC')
  .limit(10)
  .get();

// Insert a record
const user = await qb.from('users').insert({
  name: 'John',
  email: 'john@example.com',
  active: true,
});

// Update a record
const affectedRows = await qb.from('users').where('id', '=', 1).update({
  name: 'John Doe',
  updated_at: new Date(),
});

// Delete a record
const affectedRows = await qb.from('users').where('id', '=', 1).delete();
```

### Redis Cache

The `RedisCache` class provides a caching interface with layered caching strategy.

```typescript
import { redisCache } from './connections/redis';

// Set a value in the cache
await redisCache.set('user:1', { id: 1, name: 'John' }, 3600);

// Get a value from the cache
const user = await redisCache.get('user:1');

// Delete a key from the cache
await redisCache.delete('user:1');

// Check if a key exists in the cache
const exists = await redisCache.exists('user:1');

// Get multiple values from the cache
const values = await redisCache.mget(['user:1', 'user:2', 'user:3']);

// Set multiple values in the cache
await redisCache.mset(
  {
    'user:1': { id: 1, name: 'John' },
    'user:2': { id: 2, name: 'Jane' },
  },
  3600
);

// Increment a counter in the cache
const newValue = await redisCache.increment('visits', 1);

// Publish a message to a channel
await redisCache.publish('user-updates', { id: 1, action: 'updated' });

// Subscribe to a channel
await redisCache.subscribe('user-updates', (message, channel) => {
  console.log(`Received message on channel ${channel}:`, message);
});
```

### Metrics Collector

The `MetricsCollector` class collects and stores metrics about database operations.

```typescript
import { metricsCollector } from './connections/metrics-collector';

// Track a PostgreSQL query
metricsCollector.trackPostgresQuery(100, false, false);

// Track a Redis operation
metricsCollector.trackRedisOperation(50, false, true);

// Track a Prisma query
metricsCollector.trackPrismaQuery(200, false);

// Update PostgreSQL pool metrics
metricsCollector.updatePostgresPoolMetrics(10, 5, 5, 0);

// Update Redis metrics
metricsCollector.updateRedisMetrics(1024 * 1024, 5);

// Get all metrics
const metrics = metricsCollector.getMetrics();

// Get a specific metric
const queryDuration = metricsCollector.getMetric('postgres.query.duration.avg');
```

### Connection Monitor

The `ConnectionMonitor` class monitors database connections and provides health information.

```typescript
import { connectionMonitor } from './connections/connection-monitor';

// Start monitoring connections
connectionMonitor.start();

// Stop monitoring connections
connectionMonitor.stop();

// Check the health of all connections
await connectionMonitor.checkHealth();

// Get the current health of all connections
const health = connectionMonitor.getCurrentHealth();

// Get the health history for a specific service
const postgresHistory = connectionMonitor.getHealthHistory('postgres');

// Check if all connections are healthy
const isHealthy = connectionMonitor.isHealthy();

// Listen for health change events
connectionMonitor.on('health-change', (service, health, previousHealth) => {
  console.log(`Health of ${service} changed from ${previousHealth.status} to ${health.status}`);
});

// Listen for connection error events
connectionMonitor.on('connection-error', (service, error) => {
  console.error(`Error in ${service} connection:`, error);
});

// Listen for connection recovery events
connectionMonitor.on('connection-recovery', service => {
  console.log(`${service} connection recovered`);
});

// Listen for failover events
connectionMonitor.on('failover', (service, from, to) => {
  console.log(`${service} failover from ${from} to ${to}`);
});
```

## Best Practices

1. **Use the Connection Wrapper**: The `db` instance from `connection-wrapper.ts` provides a high-level interface for database operations. Use it for most database interactions.

2. **Leverage the Query Builder**: The query builder provides a fluent interface for building SQL queries. Use it to build complex queries without writing raw SQL.

3. **Use Transactions**: When performing multiple related database operations, use transactions to ensure data consistency.

4. **Cache Frequently Accessed Data**: Use the Redis cache to store frequently accessed data and reduce database load.

5. **Monitor Database Health**: Use the connection monitor to track database health and receive notifications about connection issues.

6. **Track Metrics**: Use the metrics collector to track database performance and identify bottlenecks.

7. **Handle Errors Gracefully**: Use try-catch blocks to handle database errors and provide meaningful error messages.

8. **Use Type Safety**: Leverage TypeScript's type system to catch errors at compile time.

9. **Follow the Repository Pattern**: Create repository classes for each entity to encapsulate database operations.

10. **Use Dependency Injection**: Inject the database connection into your services to make them testable.
