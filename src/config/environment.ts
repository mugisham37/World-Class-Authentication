import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import { logger } from '../infrastructure/logging/logger';

/**
 * Environment configuration manager
 * Handles loading environment variables from different sources
 * with support for environment-specific configuration
 */
export class Environment {
  private static instance: Environment;
  private envCache: Record<string, string> = {};
  private initialized = false;

  private constructor() {
    // Private constructor to enforce singleton pattern
  }

  /**
   * Get the singleton instance
   */
  public static getInstance(): Environment {
    if (!Environment.instance) {
      Environment.instance = new Environment();
    }
    return Environment.instance;
  }

  /**
   * Initialize the environment configuration
   * Loads variables from .env files based on current NODE_ENV
   */
  public initialize(): void {
    if (this.initialized) {
      return;
    }

    const nodeEnv = process.env.NODE_ENV || 'development';
    const envFiles = [
      path.resolve(process.cwd(), '.env'),
      path.resolve(process.cwd(), `.env.${nodeEnv}`),
      path.resolve(process.cwd(), `.env.${nodeEnv}.local`),
    ];

    // Load each env file if it exists
    envFiles.forEach(file => {
      if (fs.existsSync(file)) {
        const result = dotenv.config({ path: file });
        if (result.error) {
          logger.error(`Error loading environment file ${file}`, { error: result.error });
        } else {
          logger.info(`Loaded environment from ${file}`);
        }
      }
    });

    // Cache all environment variables
    this.envCache = { ...process.env };
    this.initialized = true;
  }

  /**
   * Get an environment variable
   * @param key The environment variable key
   * @param defaultValue Optional default value if the key doesn't exist
   * @returns The environment variable value or the default value
   */
  public get(key: string, defaultValue?: string): string | undefined {
    if (!this.initialized) {
      this.initialize();
    }
    return this.envCache[key] || defaultValue;
  }

  /**
   * Get an environment variable as a number
   * @param key The environment variable key
   * @param defaultValue Optional default value if the key doesn't exist or isn't a valid number
   * @returns The environment variable as a number or the default value
   */
  public getNumber(key: string, defaultValue?: number): number | undefined {
    const value = this.get(key);
    if (value === undefined) {
      return defaultValue;
    }
    const num = Number(value);
    return isNaN(num) ? defaultValue : num;
  }

  /**
   * Get an environment variable as a boolean
   * @param key The environment variable key
   * @param defaultValue Optional default value if the key doesn't exist
   * @returns The environment variable as a boolean or the default value
   */
  public getBoolean(key: string, defaultValue?: boolean): boolean | undefined {
    const value = this.get(key);
    if (value === undefined) {
      return defaultValue;
    }
    return value.toLowerCase() === 'true';
  }

  /**
   * Check if an environment variable exists
   * @param key The environment variable key
   * @returns True if the environment variable exists, false otherwise
   */
  public has(key: string): boolean {
    if (!this.initialized) {
      this.initialize();
    }
    return key in this.envCache;
  }

  /**
   * Get the current environment (development, test, production)
   * @returns The current environment
   */
  public getEnvironment(): string {
    return this.get('NODE_ENV', 'development');
  }

  /**
   * Check if the current environment is production
   * @returns True if the current environment is production, false otherwise
   */
  public isProduction(): boolean {
    return this.getEnvironment() === 'production';
  }

  /**
   * Check if the current environment is development
   * @returns True if the current environment is development, false otherwise
   */
  public isDevelopment(): boolean {
    return this.getEnvironment() === 'development';
  }

  /**
   * Check if the current environment is test
   * @returns True if the current environment is test, false otherwise
   */
  public isTest(): boolean {
    return this.getEnvironment() === 'test';
  }
}

// Export a singleton instance
export const env = Environment.getInstance();
