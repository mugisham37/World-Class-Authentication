/**
 * Log level enum
 */
export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
  FATAL = 'fatal',
}

/**
 * Log entry interface
 */
export interface LogEntry {
  level: LogLevel;
  message: string;
  timestamp: string;
  context: Record<string, any> | undefined;
}

/**
 * Logger interface
 */
export interface Logger {
  debug(message: string, context?: Record<string, any>): void;
  info(message: string, context?: Record<string, any>): void;
  warn(message: string, context?: Record<string, any>): void;
  error(message: string, context?: Record<string, any>): void;
  fatal(message: string, context?: Record<string, any>): void;
}

/**
 * Console logger implementation
 */
class ConsoleLogger implements Logger {
  /**
   * Minimum log level to output
   */
  private minLevel: LogLevel;

  /**
   * Constructor
   * @param minLevel Minimum log level to output
   */
  constructor(minLevel: LogLevel = LogLevel.DEBUG) {
    this.minLevel = minLevel;
  }

  /**
   * Log a debug message
   * @param message Message to log
   * @param context Optional context
   */
  debug(message: string, context?: Record<string, any>): void {
    this.log(LogLevel.DEBUG, message, context);
  }

  /**
   * Log an info message
   * @param message Message to log
   * @param context Optional context
   */
  info(message: string, context?: Record<string, any>): void {
    this.log(LogLevel.INFO, message, context);
  }

  /**
   * Log a warning message
   * @param message Message to log
   * @param context Optional context
   */
  warn(message: string, context?: Record<string, any>): void {
    this.log(LogLevel.WARN, message, context);
  }

  /**
   * Log an error message
   * @param message Message to log
   * @param context Optional context
   */
  error(message: string, context?: Record<string, any>): void {
    this.log(LogLevel.ERROR, message, context);
  }

  /**
   * Log a fatal message
   * @param message Message to log
   * @param context Optional context
   */
  fatal(message: string, context?: Record<string, any>): void {
    this.log(LogLevel.FATAL, message, context);
  }

  /**
   * Log a message
   * @param level Log level
   * @param message Message to log
   * @param context Optional context
   */
  private log(level: LogLevel, message: string, context?: Record<string, any>): void {
    // Skip if level is below minimum
    if (!this.shouldLog(level)) {
      return;
    }

    const entry: LogEntry = {
      level,
      message,
      timestamp: new Date().toISOString(),
      context,
    };

    this.output(entry);
  }

  /**
   * Check if a log level should be logged
   * @param level Log level to check
   * @returns True if the level should be logged
   */
  private shouldLog(level: LogLevel): boolean {
    const levels = [LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR, LogLevel.FATAL];
    const minLevelIndex = levels.indexOf(this.minLevel);
    const levelIndex = levels.indexOf(level);
    return levelIndex >= minLevelIndex;
  }

  /**
   * Output a log entry
   * @param entry Log entry to output
   */
  private output(entry: LogEntry): void {
    const { level, message, timestamp, context } = entry;

    // Format the log message
    let formattedMessage = `[${timestamp}] ${level.toUpperCase()}: ${message}`;

    // Add context if provided
    if (context) {
      formattedMessage += `\n${JSON.stringify(context, null, 2)}`;
    }

    // Output to console
    switch (level) {
      case LogLevel.DEBUG:
        console.debug(formattedMessage);
        break;
      case LogLevel.INFO:
        console.info(formattedMessage);
        break;
      case LogLevel.WARN:
        console.warn(formattedMessage);
        break;
      case LogLevel.ERROR:
      case LogLevel.FATAL:
        console.error(formattedMessage);
        break;
    }
  }
}

/**
 * Get the minimum log level from environment
 * @returns Minimum log level
 */
function getMinLogLevel(): LogLevel {
  const envLevel = process.env['LOG_LEVEL']?.toLowerCase();

  switch (envLevel) {
    case 'debug':
      return LogLevel.DEBUG;
    case 'info':
      return LogLevel.INFO;
    case 'warn':
      return LogLevel.WARN;
    case 'error':
      return LogLevel.ERROR;
    case 'fatal':
      return LogLevel.FATAL;
    default:
      // Default to INFO in production, DEBUG otherwise
      return process.env['NODE_ENV'] === 'production' ? LogLevel.INFO : LogLevel.DEBUG;
  }
}

// Create and export the logger instance
export const logger: Logger = new ConsoleLogger(getMinLogLevel());
