# World-Class Authentication Configuration System: Line-by-Line Explanation

This document provides a detailed explanation of each file in our configuration system, breaking down the code line by line for someone without programming experience. We'll explore what each part does and why it's important.

## Table of Contents

1. [Environment Manager (environment.ts)](#1-environment-manager-environmentts)
2. [Validation Utilities (validation.ts)](#2-validation-utilities-validationts)
3. [Configuration Index (index.ts)](#3-configuration-index-indexts)
4. [App Configuration (app-config.ts)](#4-app-configuration-app-configts)
5. [Security Configuration (security-config.ts)](#5-security-configuration-security-configts)
6. [Database Configuration (database-config.ts)](#6-database-configuration-database-configts)
7. [OAuth Configuration (oauth-config.ts)](#7-oauth-configuration-oauth-configts)
8. [Other Configuration Modules](#8-other-configuration-modules)

---

## 1. Environment Manager (environment.ts)

This file is the foundation of our configuration system. It's responsible for loading environment variables from `.env` files and providing them to the rest of the application.

```typescript
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import { logger } from '../infrastructure/logging/logger';
```

**What this does:** These lines bring in tools we need:

- `dotenv`: A tool that loads environment variables from `.env` files
- `path`: Helps us work with file and directory paths
- `fs`: Allows us to check if files exist
- `logger`: A tool for logging messages and errors

```typescript
export class Environment {
  private static instance: Environment;
  private envCache: Record<string, string> = {};
  private initialized = false;
```

**What this does:**

- We're creating a blueprint for our Environment manager
- `private static instance`: This will hold the single instance of our Environment manager
- `private envCache`: This is like a memory box that will store all our environment variables
- `private initialized`: This is a flag that tells us if we've already loaded our environment variables

```typescript
  private constructor() {
    // Private constructor to enforce singleton pattern
  }
```

**What this does:** This is a special function that creates a new Environment manager. It's marked as `private` which means you can't directly create a new Environment manager from outside this file. This enforces the "singleton pattern" - ensuring we only ever have one Environment manager in our application.

```typescript
  public static getInstance(): Environment {
    if (!Environment.instance) {
      Environment.instance = new Environment();
    }
    return Environment.instance;
  }
```

**What this does:** This is how you get access to the Environment manager:

- It first checks if an instance already exists
- If not, it creates a new one
- Then it returns the instance
- This ensures that no matter how many times you call `getInstance()`, you always get the same instance

```typescript
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
```

**What this does:**

- This function loads environment variables from files
- It first checks if we've already initialized to avoid doing it twice
- `nodeEnv` gets the current environment (development, production, test) or defaults to 'development'
- `envFiles` creates a list of files to check for environment variables:
  1. `.env` (base configuration)
  2. `.env.development` or `.env.production` (environment-specific)
  3. `.env.development.local` or `.env.production.local` (local overrides)

```typescript
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
```

**What this does:**

- For each file in our list, we:
  1. Check if the file exists
  2. If it does, try to load environment variables from it
  3. If there's an error, log it
  4. If successful, log that we loaded the file

```typescript
    // Cache all environment variables
    this.envCache = { ...process.env };
    this.initialized = true;
  }
```

**What this does:**

- After loading all environment files, we store all environment variables in our cache
- We mark initialization as complete

```typescript
  public get(key: string, defaultValue?: string): string | undefined {
    if (!this.initialized) {
      this.initialize();
    }
    return this.envCache[key] || defaultValue;
  }
```

**What this does:**

- This function gets an environment variable by its key (name)
- If we haven't initialized yet, it calls initialize()
- It returns the value from our cache, or the default value if the key doesn't exist

```typescript
  public getNumber(key: string, defaultValue?: number): number | undefined {
    const value = this.get(key);
    if (value === undefined) {
      return defaultValue;
    }
    const num = Number(value);
    return isNaN(num) ? defaultValue : num;
  }
```

**What this does:**

- Similar to `get()`, but converts the value to a number
- If the value isn't a valid number, it returns the default value

```typescript
  public getBoolean(key: string, defaultValue?: boolean): boolean | undefined {
    const value = this.get(key);
    if (value === undefined) {
      return defaultValue;
    }
    return value.toLowerCase() === 'true';
  }
```

**What this does:**

- Similar to `get()`, but converts the value to a boolean
- It considers the string "true" (case-insensitive) as true, and everything else as false

```typescript
  public has(key: string): boolean {
    if (!this.initialized) {
      this.initialize();
    }
    return key in this.envCache;
  }
```

**What this does:**

- Checks if an environment variable exists
- Returns true if it exists, false otherwise

```typescript
  public getEnvironment(): string {
    return this.get('NODE_ENV', 'development');
  }

  public isProduction(): boolean {
    return this.getEnvironment() === 'production';
  }

  public isDevelopment(): boolean {
    return this.getEnvironment() === 'development';
  }

  public isTest(): boolean {
    return this.getEnvironment() === 'test';
  }
```

**What this does:**

- `getEnvironment()`: Gets the current environment (development, production, test)
- `isProduction()`: Checks if we're in production mode
- `isDevelopment()`: Checks if we're in development mode
- `isTest()`: Checks if we're in test mode

```typescript
// Export a singleton instance
export const env = Environment.getInstance();
```

**What this does:**

- Creates a single instance of our Environment manager
- Exports it as `env` so other files can use it

## 2. Validation Utilities (validation.ts)

This file provides tools for validating configuration values, ensuring they meet our requirements before the application starts.

```typescript
import { z } from 'zod';
```

**What this does:** Imports Zod, a library for data validation. Think of it as a security guard that checks if data meets our requirements.

```typescript
export function validateConfig<T extends z.ZodType>(schema: T, config: any): z.infer<T> {
  try {
    // Parse and validate the configuration
    return schema.parse(config);
  } catch (error) {
```

**What this does:**

- This function takes two things:
  1. A schema (a set of rules that define what valid data looks like)
  2. A configuration object (the data we want to validate)
- It tries to validate the configuration against the schema

```typescript
    if (error instanceof z.ZodError) {
      console.error('\n❌ Configuration validation failed:');

      // Format and log each validation error
      error.errors.forEach((err) => {
        const path = err.path.join('.');
        console.error(`  - ${path}: ${err.message}`);
      });
```

**What this does:**

- If validation fails, we:
  1. Print a header message
  2. For each error, print the path to the invalid value and the error message
  3. For example: `jwt.accessTokenSecret: String must contain at least 32 character(s)`

```typescript
      // Provide guidance on fixing the errors
      console.error('\nPlease check your environment variables and ensure they match the expected types.');
      console.error('The application cannot start with invalid configuration.\n');

      // Exit the process to prevent running with invalid configuration
      process.exit(1);
    }
```

**What this does:**

- Prints guidance on how to fix the errors
- Exits the application with an error code
- This prevents the application from running with invalid configuration, which could cause problems later

```typescript
    // Re-throw unexpected errors
    throw error;
  }
}
```

**What this does:**

- If the error isn't a validation error, we pass it along to be handled elsewhere

```typescript
export function validateInput<T extends z.ZodType>(schema: T, data: any): z.infer<T> {
  try {
    return schema.parse(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      // Transform Zod errors into a more API-friendly format
      const formattedErrors = error.errors.reduce((acc, err) => {
        const path = err.path.join('.');
        acc[path] = err.message;
        return acc;
      }, {} as Record<string, string>);
```

**What this does:**

- Similar to `validateConfig()`, but designed for validating user input in API requests
- If validation fails, it formats the errors in a way that's easier to return in an API response

```typescript
      // Throw a formatted error object that can be caught by API error middleware
      throw {
        status: 400,
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        errors: formattedErrors,
      };
    }

    throw error;
  }
}
```

**What this does:**

- Throws a formatted error object with:
  - HTTP status code (400 Bad Request)
  - Error code
  - Error message
  - Detailed errors for each invalid field
- This can be caught by API error handling middleware and returned to the client

```typescript
export function createPartialValidator<T extends z.ZodType>(schema: T): z.ZodObject<any> {
  if (schema instanceof z.ZodObject) {
    return schema.partial();
  }
  throw new Error('Schema must be a Zod object schema');
}
```

**What this does:**

- Takes a schema and makes all its properties optional
- This is useful for validating partial updates to resources
- For example, if a user wants to update just their name but not their email

## 3. Configuration Index (index.ts)

This file serves as the central hub for all configuration, making it easy to import what you need.

```typescript
/**
 * Configuration System
 *
 * This module exports a unified configuration system that provides strongly-typed
 * access to all application configuration settings. The configuration is loaded from
 * environment variables and validated using Zod schemas.
 *
 * Features:
 * - Type-safe configuration with Zod validation
 * - Environment-specific configuration (.env, .env.development, .env.production, etc.)
 * - Default values for all configuration options
 * - Comprehensive validation with helpful error messages
 * - Modular configuration organized by domain
 */
```

**What this does:**

- This is a documentation comment that explains what the configuration system does
- It lists the key features of the system

```typescript
// Export environment utilities
export { env } from './environment';

// Helper functions for environment detection
export const isDevelopment = (): boolean => env.isDevelopment();
export const isProduction = (): boolean => env.isProduction();
export const isTest = (): boolean => env.isTest();
```

**What this does:**

- Exports the `env` object from the environment.ts file
- Creates and exports helper functions for checking the current environment
- These functions make it easier to write environment-specific code

```typescript
// Export all configuration modules
export { appConfig } from './app-config';
export { auditConfig } from './audit-config';
export { complianceConfig } from './compliance-config';
export { dbConfig } from './database-config';
export { mfaConfig } from './mfa-config';
export { oauthConfig } from './oauth-config';
export { performanceConfig } from './performance-config';
export { quantumConfig } from './quantum-config';
export { recoveryConfig } from './recovery-config';
export { riskConfig } from './risk-config';
export { samlConfig } from './saml-config';
export { securityConfig } from './security-config';
```

**What this does:**

- Exports all the different configuration modules
- This allows other parts of the application to import specific configurations as needed

```typescript
// Export configuration types
export type { AppConfig } from './app-config';
export type { AuditConfig } from './audit-config';
export type { ComplianceConfig } from './compliance-config';
export type { DatabaseConfig } from './database-config';
export type { Environment } from './environment';
export type { MfaConfig } from './mfa-config';
export type { OAuthConfig } from './oauth-config';
export type { PerformanceConfig } from './performance-config';
export type { QuantumConfig } from './quantum-config';
export type { RecoveryConfig } from './recovery-config';
export type { RiskConfig } from './risk-config';
export type { SamlConfig } from './saml-config';
export type { SecurityConfig } from './security-config';
```

**What this does:**

- Exports the TypeScript types for each configuration module
- This allows other parts of the application to use these types for type checking

## 4. App Configuration (app-config.ts)

This file defines the core application settings like port, name, and API prefix.

```typescript
import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();
```

**What this does:**

- Imports the tools we need:
  - `z` from Zod for validation
  - `validateConfig` from our validation utilities
  - `env` from our environment manager
- Initializes the environment to ensure environment variables are loaded

```typescript
// Define app config schema with Zod
const appConfigSchema = z.object({
  app: z.object({
    name: z.string().default('World-Class-Authentication'),
    environment: z.enum(['development', 'test', 'production']).default('development'),
    port: z.number().int().positive().default(3000),
    apiPrefix: z.string().default('/api/v1'),
    url: z.string().url().optional(),
  }),
```

**What this does:**

- Defines a schema for app configuration
- The schema has an `app` object with:
  - `name`: A string with default 'World-Class-Authentication'
  - `environment`: One of 'development', 'test', or 'production', defaulting to 'development'
  - `port`: A positive integer with default 3000
  - `apiPrefix`: A string with default '/api/v1'
  - `url`: An optional URL string

```typescript
  logging: z.object({
    level: z.enum(['error', 'warn', 'info', 'http', 'debug']).default('info'),
    format: z.enum(['json', 'pretty']).default('pretty'),
    enableConsole: z.boolean().default(true),
    enableFile: z.boolean().default(false),
    filePath: z.string().optional(),
  }),
```

**What this does:**

- Defines logging configuration with:
  - `level`: The minimum log level to record
  - `format`: How logs should be formatted
  - `enableConsole`: Whether to log to the console
  - `enableFile`: Whether to log to a file
  - `filePath`: Where to save log files (optional)

```typescript
  cors: z.object({
    origin: z.union([z.string(), z.array(z.string())]).default('*'),
    methods: z.array(z.string()).default(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']),
    allowedHeaders: z.array(z.string()).default(['Content-Type', 'Authorization']),
    exposedHeaders: z.array(z.string()).default([]),
    credentials: z.boolean().default(true),
    maxAge: z.number().int().positive().default(86400),
  }),
```

**What this does:**

- Defines Cross-Origin Resource Sharing (CORS) configuration:
  - `origin`: Which domains can access the API
  - `methods`: Which HTTP methods are allowed
  - `allowedHeaders`: Which headers clients can send
  - `exposedHeaders`: Which headers clients can read
  - `credentials`: Whether to allow credentials (cookies, auth headers)
  - `maxAge`: How long browsers should cache CORS responses

```typescript
  rateLimiting: z.object({
    windowMs: z.number().int().positive().default(15 * 60 * 1000), // 15 minutes
    max: z.number().int().positive().default(100), // 100 requests per windowMs
  }),
```

**What this does:**

- Defines rate limiting configuration:
  - `windowMs`: The time window for rate limiting (15 minutes by default)
  - `max`: Maximum number of requests allowed in the window (100 by default)

```typescript
  swagger: z.object({
    enabled: z.boolean().default(true),
    title: z.string().default('World-Class-Authentication API'),
    description: z.string().default('API documentation for World-Class-Authentication'),
    version: z.string().default('1.0.0'),
    path: z.string().default('/api-docs'),
  }),
});
```

**What this does:**

- Defines Swagger (API documentation) configuration:
  - `enabled`: Whether to enable Swagger
  - `title`: The title of the API documentation
  - `description`: A description of the API
  - `version`: The API version
  - `path`: Where to serve the documentation

```typescript
// Parse and validate environment variables
const rawConfig = {
  app: {
    name: env.get('APP_NAME'),
    environment: env.get('NODE_ENV'),
    port: env.getNumber('PORT'),
    apiPrefix: env.get('API_PREFIX'),
    url: env.get('APP_URL'),
  },
```

**What this does:**

- Creates a raw configuration object by reading environment variables
- For each configuration option, it gets the corresponding environment variable

```typescript
  logging: {
    level: env.get('LOG_LEVEL'),
    format: env.get('LOG_FORMAT'),
    enableConsole: env.getBoolean('LOG_ENABLE_CONSOLE'),
    enableFile: env.getBoolean('LOG_ENABLE_FILE'),
    filePath: env.get('LOG_FILE_PATH'),
  },
```

**What this does:**

- Gets logging configuration from environment variables
- Note how it uses `getBoolean()` for boolean values

```typescript
  cors: {
    origin: env.get('CORS_ORIGIN'),
    methods: env.get('CORS_METHODS')?.split(','),
    allowedHeaders: env.get('CORS_ALLOWED_HEADERS')?.split(','),
    exposedHeaders: env.get('CORS_EXPOSED_HEADERS')?.split(','),
    credentials: env.getBoolean('CORS_CREDENTIALS'),
    maxAge: env.getNumber('CORS_MAX_AGE'),
  },
```

**What this does:**

- Gets CORS configuration from environment variables
- For array values, it splits comma-separated strings

```typescript
  rateLimiting: {
    windowMs: env.getNumber('RATE_LIMIT_WINDOW_MS'),
    max: env.getNumber('RATE_LIMIT_MAX'),
  },
  swagger: {
    enabled: env.getBoolean('SWAGGER_ENABLED'),
    title: env.get('SWAGGER_TITLE'),
    description: env.get('SWAGGER_DESCRIPTION'),
    version: env.get('SWAGGER_VERSION'),
    path: env.get('SWAGGER_PATH'),
  },
};
```

**What this does:**

- Gets rate limiting and Swagger configuration from environment variables

```typescript
// Validate and export config
export const appConfig = validateConfig(appConfigSchema, rawConfig);

// Export config type
export type AppConfig = typeof appConfig;
```

**What this does:**

- Validates the raw configuration against the schema
- If validation passes, exports the validated configuration as `appConfig`
- Also exports the TypeScript type of the configuration as `AppConfig`

## 5. Security Configuration (security-config.ts)

This file defines security-related settings like JWT configuration, password policies, and session management.

```typescript
import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Load environment variables
env.initialize();
```

**What this does:**

- Similar to app-config.ts, imports necessary tools and initializes the environment

```typescript
// Define security config schema with Zod
const securityConfigSchema = z.object({
  jwt: z.object({
    accessTokenSecret: z.string().min(32),
    refreshTokenSecret: z.string().min(32),
    accessTokenExpiresIn: z.string().default('15m'), // 15 minutes
    refreshTokenExpiresIn: z.string().default('7d'), // 7 days
    issuer: z.string().default('auth-system'),
    audience: z.string().default('auth-system-client'),
  }),
```

**What this does:**

- Defines JWT (JSON Web Token) configuration:
  - `accessTokenSecret`: A secret key for signing access tokens (must be at least 32 characters)
  - `refreshTokenSecret`: A secret key for signing refresh tokens (must be at least 32 characters)
  - `accessTokenExpiresIn`: How long access tokens are valid (15 minutes by default)
  - `refreshTokenExpiresIn`: How long refresh tokens are valid (7 days by default)
  - `issuer`: Who issued the token
  - `audience`: Who the token is intended for

```typescript
  password: z.object({
    saltRounds: z.coerce.number().int().positive().default(12),
    pepper: z.string().min(32).optional(),
    minLength: z.coerce.number().int().positive().default(8),
    requireLowercase: z.boolean().default(true),
    requireUppercase: z.boolean().default(true),
    requireNumbers: z.boolean().default(true),
    requireSymbols: z.boolean().default(true),
    maxHistory: z.coerce.number().int().nonnegative().default(5),
  }),
```

**What this does:**

- Defines password policy configuration:
  - `saltRounds`: How many rounds of hashing to use (higher is more secure but slower)
  - `pepper`: An optional additional secret for password hashing
  - `minLength`: Minimum password length
  - `requireLowercase`, `requireUppercase`, `requireNumbers`, `requireSymbols`: Password complexity requirements
  - `maxHistory`: How many previous passwords to remember (to prevent reuse)

```typescript
  session: z.object({
    cookieName: z.string().default('auth.session'),
    cookieSecure: z.boolean().default(true),
    cookieHttpOnly: z.boolean().default(true),
    cookieSameSite: z.enum(['strict', 'lax', 'none']).default('strict'),
    cookiePath: z.string().default('/'),
    cookieMaxAge: z.coerce.number().int().positive().default(86400 * 1000), // 24 hours
    absoluteTimeout: z.coerce.number().int().positive().default(8 * 60 * 60 * 1000), // 8 hours
    idleTimeout: z.coerce.number().int().positive().default(15 * 60 * 1000), // 15 minutes
  }),
```

**What this does:**

- Defines session management configuration:
  - `cookieName`: The name of the session cookie
  - `cookieSecure`: Whether the cookie should only be sent over HTTPS
  - `cookieHttpOnly`: Whether the cookie should be accessible only via HTTP (not JavaScript)
  - `cookieSameSite`: Controls when cookies are sent with cross-site requests
  - `cookiePath`: The path for which the cookie is valid
  - `cookieMaxAge`: How long the cookie is valid
  - `absoluteTimeout`: Maximum session duration regardless of activity
  - `idleTimeout`: How long a session can be idle before expiring

```typescript
  rateLimit: z.object({
    login: z.object({
      windowMs: z.coerce.number().int().positive().default(15 * 60 * 1000), // 15 minutes
      max: z.coerce.number().int().positive().default(5), // 5 attempts per windowMs
      skipSuccessfulRequests: z.boolean().default(true),
    }),
    registration: z.object({
      windowMs: z.coerce.number().int().positive().default(60 * 60 * 1000), // 1 hour
      max: z.coerce.number().int().positive().default(3), // 3 attempts per windowMs
    }),
    passwordReset: z.object({
      windowMs: z.coerce.number().int().positive().default(60 * 60 * 1000), // 1 hour
      max: z.coerce.number().int().positive().default(3), // 3 attempts per windowMs
    }),
  }),
```

**What this does:**

- Defines rate limiting for security-sensitive operations:
  - `login`: Limits login attempts to prevent brute force attacks
  - `registration`: Limits account creation to prevent spam
  - `passwordReset`: Limits password reset requests to prevent abuse

```typescript
  encryption: z.object({
    algorithm: z.string().default('aes-256-gcm'),
    secretKey: z.string().min(32),
    ivLength: z.coerce.number().int().positive().default(16),
  }),
});
```

**What this does:**

- Defines encryption settings for sensitive data:
  - `algorithm`: The encryption algorithm to use
  - `secretKey`: The secret key for encryption (must be at least 32 characters)
  - `ivLength`: The length of the initialization vector

```typescript
// Parse and validate environment variables
const rawConfig = {
  jwt: {
    accessTokenSecret: env.get('JWT_ACCESS_TOKEN_SECRET'),
    refreshTokenSecret: env.get('JWT_REFRESH_TOKEN_SECRET'),
    accessTokenExpiresIn: env.get('JWT_ACCESS_TOKEN_EXPIRES_IN'),
    refreshTokenExpiresIn: env.get('JWT_REFRESH_TOKEN_EXPIRES_IN'),
    issuer: env.get('JWT_ISSUER'),
    audience: env.get('JWT_AUDIENCE'),
  },
  // ... similar for other sections
};

// Validate and export config
export const securityConfig = validateConfig(securityConfigSchema, rawConfig);

// Export config type
export type SecurityConfig = typeof securityConfig;
```

**What this does:**

- Gets security configuration from environment variables
- Validates the configuration against the schema
- Exports the validated configuration and its type

## 6. Database Configuration (database-config.ts)

This file defines database connection settings for PostgreSQL and Redis.

```typescript
import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Load environment variables
env.initialize();
```

**What this does:**

- Similar to other config files, imports necessary tools and initializes the environment

```typescript
// Define database config schema with Zod
const databaseConfigSchema = z.object({
  postgres: z.object({
    host: z.string().default('localhost'),
    port: z.coerce.number().int().positive().default(5432),
    username: z.string(),
    password: z.string(),
    database: z.string(),
    ssl: z.boolean().default(false),
    poolSize: z.coerce.number().int().positive().default(10),
    idleTimeoutMillis: z.coerce.number().int().positive().default(30000),
    connectionTimeoutMillis: z.coerce.number().int().positive().default(2000),
  }),
```

**What this does:**

- Defines PostgreSQL database configuration:
  - Connection details (host, port, username, password, database)
  - SSL settings
  - Connection pool settings (poolSize, timeouts)

```typescript
  redis: z.object({
    host: z.string().default('localhost'),
    port: z.coerce.number().int().positive().default(6379),
    password: z.string().optional(),
    db: z.coerce.number().int().nonnegative().default(0),
    keyPrefix: z.string().default('auth:'),
    ttl: z.coerce.number().int().positive().default(86400), // 24 hours
  }),
});
```

**What this does:**

- Defines Redis configuration:
  - Connection details (host, port, password)
  - Database number
  - Key prefix (to namespace keys)
  - Default TTL (time-to-live) for cached items

```typescript
// Parse and validate environment variables
const rawConfig = {
  postgres: {
    host: env.get('POSTGRES_HOST'),
    port: env.get('POSTGRES_PORT'),
    username: env.get('POSTGRES_USER'),
    password: env.get('POSTGRES_PASSWORD'),
    database: env.get('POSTGRES_DB'),
    ssl: env.get('POSTGRES_SSL') === 'true',
    poolSize: env.get('POSTGRES_POOL_SIZE'),
    idleTimeoutMillis: env.get('POSTGRES_IDLE_TIMEOUT'),
    connectionTimeoutMillis: env.get('POSTGRES_CONNECTION_TIMEOUT'),
  },
  redis: {
    host: env.get('REDIS_HOST'),
    port: env.get('REDIS_PORT'),
    password: env.get('REDIS_PASSWORD'),
    db: env.get('REDIS_DB'),
    keyPrefix: env.get('REDIS_KEY_PREFIX'),
    ttl: env.get('REDIS_TTL'),
  },
};

// Validate and export config
export const dbConfig = validateConfig(databaseConfigSchema, rawConfig);

// Export config type
export type DatabaseConfig = typeof dbConfig;
```

**What this does:**

- Gets database configuration from environment variables
- Validates the configuration against the schema
- Exports the validated configuration and its type

## 7. OAuth Configuration (oauth-config.ts)

This file defines OAuth 2.0 and OpenID Connect settings for authentication and authorization.

```typescript
import { z } from 'zod';
import { validateConfig } from '../utils/validation';
import { env } from './environment';

// Initialize environment
env.initialize();
```

**What this does:**

- Similar to other config files, imports necessary tools and initializes the environment

```typescript
// Define OAuth config schema with Zod
const oauthConfigSchema = z.object({
  authorizationCodeTtl: z.number().int().positive().default(10 * 60), // 10 minutes
  accessTokenTtl: z.number().int().positive().default(60 * 60), // 1 hour
  refreshTokenTtl: z.number().int().positive().default(30 * 24 * 60 * 60), // 30 days
  idTokenTtl: z.number().int().positive().default(60 * 60), // 1 hour
  jwtAlgorithm: z.string().default('RS256'),
```

**What this does:**

- Defines OAuth token settings:
  - TTL (time-to-live) for different token types
  - JWT signing algorithm

```typescript
  supportedResponseTypes: z.array(z.string()).default([
    'code',
    'token',
```
