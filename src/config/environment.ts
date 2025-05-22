import dotenv from 'dotenv';
import { z } from 'zod';
import path from 'path';
import fs from 'fs';

// Determine which .env file to load based on NODE_ENV
const envFile = process.env['NODE_ENV'] === 'test' ? '.env.test' : '.env';
const envPath = path.resolve(process.cwd(), envFile);

// Check if the file exists, if not, fall back to .env.example
if (!fs.existsSync(envPath)) {
  const examplePath = path.resolve(process.cwd(), '.env.example');
  if (fs.existsSync(examplePath)) {
    console.warn(`${envFile} not found, using .env.example instead`);
    dotenv.config({ path: examplePath });
  } else {
    console.warn(`Neither ${envFile} nor .env.example found`);
    dotenv.config();
  }
} else {
  dotenv.config({ path: envPath });
}

// Define environment schema with validation
const envSchema = z.object({
  // Application
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(3000),
  API_VERSION: z.string().default('v1'),
  APP_NAME: z.string().default('WorldClassAuth'),
  APP_URL: z.string().url(),
  
  // Database
  DATABASE_URL: z.string().url(),
  REDIS_URL: z.string().url(),
  
  // JWT
  JWT_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),
  JWT_EXPIRES_IN: z.string().default('15m'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),
  
  // Email
  EMAIL_SERVICE: z.string(),
  EMAIL_API_KEY: z.string(),
  EMAIL_FROM: z.string().email(),
  
  // Security
  BCRYPT_ROUNDS: z.coerce.number().default(12),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().default(900000),
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().default(100),
  CORS_ORIGINS: z.string().transform(val => val.split(',')).default('http://localhost:3000'),
  
  // Monitoring
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  SENTRY_DSN: z.string().optional(),
});

// Parse and validate environment variables
export type Environment = z.infer<typeof envSchema>;

// Define env variable outside the try block
export let env: Environment;

// Try to parse environment variables, with helpful error messages
try {
  env = envSchema.parse(process.env);
} catch (error) {
  if (error instanceof z.ZodError) {
    const missingVars = error.errors.map(e => `${e.path.join('.')}: ${e.message}`).join('\n');
    console.error(`❌ Invalid environment variables:\n${missingVars}`);
    process.exit(1);
  }
  throw error;
}

// Helper functions
export const isDevelopment = env.NODE_ENV === 'development';
export const isProduction = env.NODE_ENV === 'production';
export const isTest = env.NODE_ENV === 'test';
