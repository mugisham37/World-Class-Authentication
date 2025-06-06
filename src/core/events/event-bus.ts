import EventEmitter from 'events';
import { logger } from '../../infrastructure/logging/logger';
import { EventType, type EventHandler } from './event-types';
import { redisCache } from '../../data/connections/redis';

/**
 * Event Bus Service
 * Implements a robust event system with local and distributed event handling
 */
class EventBus {
  private eventEmitter: EventEmitter;
  private distributedMode: boolean;
  private readonly redisChannel = 'auth:events';
  private readonly maxRetries = 3;
  // private readonly retryDelay = 1000; // 1 second
  private readonly deadLetterQueue: Map<string, any[]> = new Map();

  constructor() {
    // Initialize event emitter with higher limit to avoid memory leak warnings
    this.eventEmitter = new EventEmitter();
    this.eventEmitter.setMaxListeners(100);

    // Determine if we should use distributed events (Redis)
    this.distributedMode = process.env['EVENT_BUS_DISTRIBUTED'] === 'true';
  }

  /**
   * Initialize the event bus
   */
  public async initialize(): Promise<void> {
    logger.info('Event bus initializing...');

    try {
      // Set up distributed event handling if enabled
      if (this.distributedMode) {
        await this.setupDistributedEvents();
      }

      logger.info(
        `Event bus initialized in ${this.distributedMode ? 'distributed' : 'local'} mode`
      );
    } catch (error) {
      logger.error('Failed to initialize event bus', { error });
      throw new Error('Failed to initialize event bus');
    }
  }

  /**
   * Set up distributed event handling with Redis
   */
  private async setupDistributedEvents(): Promise<void> {
    try {
      // Subscribe to the events channel
      await redisCache.subscribe(this.redisChannel, (message, channel) => {
        try {
          const { eventType, payload } = JSON.parse(message);
          // Emit the event locally but mark it as from Redis to avoid re-publishing
          this.emitLocal(eventType, payload, true);
        } catch (error) {
          logger.error('Failed to process distributed event', { error, message, channel });
        }
      });

      logger.info('Distributed event handling set up successfully');
    } catch (error) {
      logger.error('Failed to set up distributed event handling', { error });
      this.distributedMode = false;
      logger.warn('Falling back to local-only event handling');
    }
  }

  /**
   * Emit an event
   * @param eventType Event type
   * @param payload Event payload
   */
  public emit<T>(eventType: EventType, payload: T): void {
    // Add timestamp if not present
    const enhancedPayload = {
      ...(payload as object),
      timestamp: (payload as any).timestamp || new Date(),
    };

    // Log the event
    logger.debug(`Emitting event: ${eventType}`, {
      eventType,
      payloadType: typeof payload,
      hasTimestamp: !!(payload as any).timestamp,
    });

    // Emit locally
    this.emitLocal(eventType, enhancedPayload);

    // Publish to Redis if in distributed mode
    if (this.distributedMode) {
      this.publishToRedis(eventType, enhancedPayload);
    }
  }

  /**
   * Emit an event locally
   * @param eventType Event type
   * @param payload Event payload
   * @param fromRedis Whether the event came from Redis to prevent re-publishing
   */
  private emitLocal<T>(eventType: EventType, payload: T, fromRedis = false): void {
    try {
      this.eventEmitter.emit(eventType, payload);

      // Also emit to wildcard listeners
      // Only process wildcards and potentially re-publish if not from Redis
      // This prevents infinite loops in distributed event systems
      if (!fromRedis) {
        const parts = eventType.split('.');
        while (parts.length > 0) {
          parts.pop();
          const wildcardEvent = parts.join('.') + '.*';
          if (this.eventEmitter.listenerCount(wildcardEvent) > 0) {
            this.eventEmitter.emit(wildcardEvent, { eventType, payload });
          }
        }
      }
    } catch (error) {
      logger.error(`Error in local event emission for ${eventType}`, { error, payload });

      // Add to dead letter queue
      this.addToDeadLetterQueue(eventType, payload);
    }
  }

  /**
   * Publish an event to Redis
   * @param eventType Event type
   * @param payload Event payload
   */
  private publishToRedis<T>(eventType: EventType, payload: T): void {
    try {
      redisCache
        .publish(
          this.redisChannel,
          JSON.stringify({
            eventType,
            payload,
            source: process.env['NODE_APP_INSTANCE'] || 'default',
            publishedAt: new Date(),
          })
        )
        .catch(error => {
          logger.error(`Failed to publish event to Redis: ${eventType}`, { error });

          // Add to dead letter queue
          this.addToDeadLetterQueue(eventType, payload);
        });
    } catch (error) {
      logger.error(`Error preparing Redis publication for ${eventType}`, { error });

      // Add to dead letter queue
      this.addToDeadLetterQueue(eventType, payload);
    }
  }

  /**
   * Register an event handler
   * @param eventType Event type
   * @param handler Event handler function
   */
  public on<T>(eventType: EventType | string, handler: EventHandler<T>): void {
    logger.debug(`Registering handler for event: ${eventType}`);

    // Wrap handler to catch errors
    const wrappedHandler = (payload: T) => {
      try {
        const result = handler(payload);

        // Handle promise returned by handler
        if (result instanceof Promise) {
          result.catch(error => {
            logger.error(`Error in async event handler for ${eventType}`, { error, payload });
          });
        }
      } catch (error) {
        logger.error(`Error in event handler for ${eventType}`, { error, payload });
      }
    };

    this.eventEmitter.on(eventType, wrappedHandler);
  }

  /**
   * Register a one-time event handler
   * @param eventType Event type
   * @param handler Event handler function
   */
  public once<T>(eventType: EventType | string, handler: EventHandler<T>): void {
    logger.debug(`Registering one-time handler for event: ${eventType}`);

    // Wrap handler to catch errors
    const wrappedHandler = (payload: T) => {
      try {
        const result = handler(payload);

        // Handle promise returned by handler
        if (result instanceof Promise) {
          result.catch(error => {
            logger.error(`Error in async one-time event handler for ${eventType}`, {
              error,
              payload,
            });
          });
        }
      } catch (error) {
        logger.error(`Error in one-time event handler for ${eventType}`, { error, payload });
      }
    };

    this.eventEmitter.once(eventType, wrappedHandler);
  }

  /**
   * Remove an event handler
   * @param eventType Event type
   * @param handler Event handler function
   */
  public off<T>(eventType: EventType | string, handler: EventHandler<T>): void {
    logger.debug(`Removing handler for event: ${eventType}`);
    this.eventEmitter.off(eventType, handler);
  }

  /**
   * Remove all listeners for an event type
   * @param eventType Event type
   */
  public removeAllListeners(eventType?: EventType | string): void {
    if (eventType) {
      logger.debug(`Removing all listeners for event: ${eventType}`);
      this.eventEmitter.removeAllListeners(eventType);
    } else {
      logger.debug('Removing all event listeners');
      this.eventEmitter.removeAllListeners();
    }
  }

  /**
   * Get the number of listeners for an event type
   * @param eventType Event type
   * @returns Number of listeners
   */
  public listenerCount(eventType: EventType | string): number {
    return this.eventEmitter.listenerCount(eventType);
  }

  /**
   * Add an event to the dead letter queue
   * @param eventType Event type
   * @param payload Event payload
   */
  private addToDeadLetterQueue<T>(eventType: EventType, payload: T): void {
    if (!this.deadLetterQueue.has(eventType)) {
      this.deadLetterQueue.set(eventType, []);
    }

    this.deadLetterQueue.get(eventType)!.push({
      payload,
      timestamp: new Date(),
      retries: 0,
    });

    logger.warn(`Event added to dead letter queue: ${eventType}`);
  }

  /**
   * Process the dead letter queue
   * Attempts to reprocess failed events
   */
  public async processDeadLetterQueue(): Promise<void> {
    logger.debug('Processing dead letter queue');

    for (const [eventType, events] of this.deadLetterQueue.entries()) {
      const remainingEvents = [];

      for (const event of events) {
        if (event.retries < this.maxRetries) {
          try {
            // Increment retry count
            event.retries++;

            // Try to emit the event again
            this.emit(eventType as EventType, event.payload);

            logger.info(`Successfully reprocessed event from dead letter queue: ${eventType}`, {
              retryCount: event.retries,
            });
          } catch (error) {
            logger.error(`Failed to reprocess event from dead letter queue: ${eventType}`, {
              error,
              retryCount: event.retries,
            });

            // Keep in queue for next attempt
            remainingEvents.push(event);
          }
        } else {
          logger.error(`Event exceeded max retries and will be dropped: ${eventType}`, {
            payload: event.payload,
            maxRetries: this.maxRetries,
          });

          // Log to persistent storage or alert system in a real implementation
        }
      }

      if (remainingEvents.length > 0) {
        this.deadLetterQueue.set(eventType, remainingEvents);
      } else {
        this.deadLetterQueue.delete(eventType);
      }
    }
  }

  /**
   * Shutdown the event bus
   */
  public async shutdown(): Promise<void> {
    logger.info('Shutting down event bus');

    // Process any remaining events in the dead letter queue
    await this.processDeadLetterQueue();

    // Unsubscribe from Redis if in distributed mode
    if (this.distributedMode) {
      try {
        await redisCache.unsubscribe(this.redisChannel);
        logger.info('Unsubscribed from Redis events channel');
      } catch (error) {
        logger.error('Failed to unsubscribe from Redis events channel', { error });
      }
    }

    // Remove all listeners
    this.removeAllListeners();

    logger.info('Event bus shut down successfully');
  }
}

// Create a singleton instance
const eventBus = new EventBus();

// Export the singleton instance and convenience methods
export { eventBus };

/**
 * Initialize the event bus
 */
export const initializeEventBus = async (): Promise<void> => {
  await eventBus.initialize();
};

/**
 * Emit an event
 * @param eventType Event type
 * @param payload Event payload
 */
export const emitEvent = <T>(eventType: EventType, payload: T): void => {
  eventBus.emit(eventType, payload);
};

/**
 * Register an event handler
 * @param eventType Event type
 * @param handler Event handler function
 */
export const registerEventHandler = <T>(
  eventType: EventType | string,
  handler: EventHandler<T>
): void => {
  eventBus.on(eventType, handler);
};

/**
 * Register a one-time event handler
 * @param eventType Event type
 * @param handler Event handler function
 */
export const registerOneTimeEventHandler = <T>(
  eventType: EventType | string,
  handler: EventHandler<T>
): void => {
  eventBus.once(eventType, handler);
};

/**
 * Remove an event handler
 * @param eventType Event type
 * @param handler Event handler function
 */
export const removeEventHandler = <T>(
  eventType: EventType | string,
  handler: EventHandler<T>
): void => {
  eventBus.off(eventType, handler);
};

/**
 * Shutdown the event bus
 */
export const shutdownEventBus = async (): Promise<void> => {
  await eventBus.shutdown();
};
